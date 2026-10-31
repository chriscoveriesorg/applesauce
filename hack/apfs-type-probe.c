/*
 * Probe the AppleFSCompression private API on a DISPOSABLE APFS image only.
 * Undocumented type requests can panic the HOST kernel, not just this process.
 *
 * Compression.framework algorithm values are unrelated to decmpfs type IDs.
 * We ask the filesystem's own compressor to write files; we never synthesize
 * xattrs, and matching a requested ID does not identify the codec behind it.
 *
 * Write and verify are separate processes. The wrapper must detach the image
 * and reattach it read-only between them. Immediate reads of freshly compressed
 * files can hit the old uncompressed vnode/page cache and prove nothing about
 * kernel decoding of the stored representation.
 *
 * Interface signatures are based on Siguza/fscmp's reverse-engineered
 * AppleFSCompression header (MIT). Apple may change this private ABI.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define SAMPLE_SIZE (256 * 1024)

typedef void *(*create_queue_fn)(const void *, const void *, const void *,
                                 const void *, CFDictionaryRef);
typedef bool (*compress_file_fn)(void *, const char *, const char *);
typedef void (*finish_queue_fn)(void *);
typedef int (*query_type_fn)(const char *, uint32_t *);

static void probe_timeout(int signal_number) {
    (void)signal_number;
    static const char message[] =
        "Private APFS helper exceeded 120 seconds; stopping the process. "
        "A host-kernel hang may not be interruptible.\n";
    /* write/_exit are async-signal-safe; stdio and framework cleanup are not. */
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    _exit(124);
}

static bool write_all(int fd, const uint8_t *src, size_t size) {
    while (size > 0) {
        ssize_t written = write(fd, src, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        src += (size_t)written;
        size -= (size_t)written;
    }
    return true;
}

static bool verify_file(const char *path, const uint8_t *original, size_t size) {
    uint8_t buf[4096];
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;

    struct stat st;
    bool valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
                 st.st_nlink == 1 && st.st_size == (off_t)size;
    size_t offset = 0;
    while (valid && offset < size) {
        size_t remaining = size - offset;
        size_t wanted = remaining < sizeof(buf) ? remaining : sizeof(buf);
        ssize_t got = read(fd, buf, wanted);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0 || memcmp(buf, original + offset, (size_t)got) != 0) {
            valid = false;
            break;
        }
        offset += (size_t)got;
    }
    if (valid) {
        ssize_t extra;
        do {
            extra = read(fd, buf, 1);
        } while (extra < 0 && errno == EINTR);
        if (extra != 0) valid = false;
    }
    if (close(fd) != 0) valid = false;
    return valid;
}

static bool probe_mount(const char *mount, bool verify) {
    struct statfs volume;
    if (statfs(mount, &volume) != 0 || strcmp(volume.f_fstypename, "apfs") != 0) {
        fprintf(stderr, "Refusing to run: the probe mount must be APFS.\n");
        return false;
    }
    if (strcmp(volume.f_mntonname, mount) != 0 ||
        strstr(volume.f_mntonname, "applesauce-probe") == NULL) {
        fprintf(stderr, "Refusing to run outside a dedicated applesauce-probe APFS mount.\n");
        return false;
    }
    bool readonly = (volume.f_flags & MNT_RDONLY) != 0;
    if (verify != readonly) {
        fputs(verify ?
                "Verification requires a fresh READ-ONLY remount of the test image.\n" :
                "The write phase requires a writable disposable test image.\n", stderr);
        return false;
    }
    char marker_path[PATH_MAX];
    int marker_len = snprintf(marker_path, sizeof(marker_path),
                             "%s/.applesauce-disposable-image", mount);
    struct stat marker;
    if (marker_len < 0 || (size_t)marker_len >= sizeof(marker_path) ||
        lstat(marker_path, &marker) != 0 || !S_ISREG(marker.st_mode) ||
        marker.st_nlink != 1) {
        fprintf(stderr, "Refusing to run without the regular disposable test-image marker.\n");
        return false;
    }
    return true;
}

static bool compress_sample(const char *path, uint32_t requested,
                            create_queue_fn create_queue,
                            compress_file_fn compress_file,
                            finish_queue_fn finish_queue) {
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef type_string = CFStringCreateWithFormat(NULL, NULL, CFSTR("%u"), requested);
    const int level = 9;
    CFNumberRef level_number = CFNumberCreate(NULL, kCFNumberIntType, &level);
    if (!options || !type_string || !level_number) {
        fprintf(stderr, "Failed to allocate CoreFoundation options.\n");
        if (options) CFRelease(options);
        if (type_string) CFRelease(type_string);
        if (level_number) CFRelease(level_number);
        return false;
    }
    CFDictionarySetValue(options, CFSTR("CompressionTypes"), type_string);
    CFDictionarySetValue(options, CFSTR("CompressionLevel"), level_number);
    CFRelease(type_string);
    CFRelease(level_number);

    void *queue = create_queue(NULL, NULL, NULL, NULL, options);
    bool accepted = queue && compress_file(queue, path, NULL);
    if (queue) finish_queue(queue);
    CFRelease(options);
    return accepted;
}

int main(int argc, char **argv) {
    bool verify = argc >= 2 && strcmp(argv[1], "--verify") == 0;
    bool write_mode = argc >= 2 && strcmp(argv[1], "--write") == 0;
    bool candidates = argc == 4 && strcmp(argv[2], "--candidates") == 0;
    if ((!verify && !write_mode) || (argc != 3 && !candidates)) {
        fprintf(stderr, "Usage: apfs-type-probe --write|--verify [--candidates] /path/to/disposable/apfs/mount\n");
        return 2;
    }
    const char *mount = argv[argc - 1];
    if (!probe_mount(mount, verify)) return 2;

    struct sigaction timeout_action = {0};
    timeout_action.sa_handler = probe_timeout;
    sigemptyset(&timeout_action.sa_mask);
    if (sigaction(SIGALRM, &timeout_action, NULL) != 0) {
        perror("sigaction");
        return 2;
    }
    /* This bounds interruptible userspace work, NOT a kernel panic/hang. */
    alarm(120);

    void *framework = dlopen(
        "/System/Library/PrivateFrameworks/AppleFSCompression.framework/AppleFSCompression",
        RTLD_NOW | RTLD_LOCAL);
    if (!framework) {
        fprintf(stderr, "AppleFSCompression private framework unavailable: %s\n", dlerror());
        return 2;
    }

    create_queue_fn create_queue = (create_queue_fn)dlsym(framework, "CreateCompressionQueue");
    compress_file_fn compress_file = (compress_file_fn)dlsym(framework, "CompressFile");
    finish_queue_fn finish_queue = (finish_queue_fn)dlsym(framework, "FinishCompressionAndCleanUp");
    query_type_fn query_type = (query_type_fn)dlsym(framework, "queryCompressionType");
    if (!query_type || (!verify && (!create_queue || !compress_file || !finish_queue))) {
        fprintf(stderr, "Required private AppleFSCompression API symbols unavailable.\n");
        dlclose(framework);
        return 2;
    }

    const char pattern[] =
        "{\"role\":\"assistant\",\"text\":\"APFS compression makes chat logs "
        "smaller while preserving transparent reads.\"}\n";
    uint8_t *sample = malloc(SAMPLE_SIZE);
    if (!sample) {
        perror("malloc");
        dlclose(framework);
        return 2;
    }
    for (size_t i = 0; i < SAMPLE_SIZE; ++i) {
        sample[i] = (uint8_t)pattern[i % (sizeof(pattern) - 1)];
    }

    /* 12 = LZFSE and 14 = LZBitmap resource-fork controls.
     * 15..22 are additional requests, NOT assumed Raven/Mesh encodings.
     * In particular, type 15/16 support has been observed for framed LZ4.
     * Even a matching stored ID needs independent codec identification. */
    const uint32_t types[] = {12, 14, 15, 16, 17, 18, 19, 20, 21, 22};
    const size_t count = candidates ? sizeof(types) / sizeof(types[0]) : 2;
    puts("phase\trequested_type\tapi_accepted\ttype_query_ok\tstored_type\tuf_compressed\tlogical_bytes\tallocated_bytes\treadback\tresult");
    fflush(stdout);

    unsigned int candidate_hits = 0;
    int result_code = 0;
    for (size_t i = 0; i < count; ++i) {
        uint32_t requested = types[i];
        char path[PATH_MAX];
        int len = snprintf(path, sizeof(path), "%s/type-%" PRIu32 ".jsonl", mount, requested);
        if (len < 0 || (size_t)len >= sizeof(path)) {
            fprintf(stderr, "Probe path too long.\n");
            result_code = 2;
            break;
        }

        bool accepted = false;
        if (!verify) {
            int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            bool wrote = fd >= 0 && write_all(fd, sample, SAMPLE_SIZE) && fsync(fd) == 0;
            int write_error = errno;
            bool closed = fd >= 0 && close(fd) == 0;
            if (!wrote || !closed) {
                fprintf(stderr, "Cannot write sample on test image (type %" PRIu32 "): %s\n",
                        requested, strerror(wrote ? errno : write_error));
                result_code = 2;
                break;
            }
            fprintf(stderr, "Requesting private filesystem type %" PRIu32 "; no codec identity implied.\n", requested);
            fflush(stderr);
            accepted = compress_sample(path, requested, create_queue, compress_file, finish_queue);
        }

        uint32_t stored = 0;
        bool queried = query_type(path, &stored) == 0;
        struct stat st;
        bool stat_ok = lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1;
        bool flagged = stat_ok && (st.st_flags & UF_COMPRESSED) != 0;
        bool sized = stat_ok && st.st_size == SAMPLE_SIZE;
        bool matched = queried && stored == requested && flagged && sized;
        bool bytes_ok = verify && verify_file(path, sample, SAMPLE_SIZE);
        long long disk_bytes = stat_ok ? (long long)st.st_blocks * 512LL : -1LL;
        bool saves_space = disk_bytes >= 0 && disk_bytes < SAMPLE_SIZE;
        bool passed = matched && (verify ? bytes_ok : accepted);
        if (verify && requested >= 15 && passed) ++candidate_hits;

        const char *result = !stat_ok ? "missing-or-invalid-file" :
                             !sized ? "logical-size-mismatch" :
                             verify && !bytes_ok ? "readback-failed" :
                             passed && !verify ? "pending-remount-verification" :
                             passed && saves_space ? "remount-readback-verified" :
                             passed ? "remount-verified-no-block-savings" :
                             queried && stored != 0 && stored != requested ? "different-type-stored" :
                             !queried ? "type-query-failed" :
                             "uncompressed-or-unsupported";
        printf("%s\t%" PRIu32 "\t%s\t%s\t%" PRIu32 "\t%s\t%lld\t%lld\t%s\t%s\n",
               verify ? "verify-readonly-remount" : "write", requested,
               verify ? "not-tested" : accepted ? "yes" : "no",
               queried ? "yes" : "no", queried ? stored : 0,
               flagged ? "yes" : "no", stat_ok ? (long long)st.st_size : -1LL,
               disk_bytes, verify ? bytes_ok ? "OK" : "FAIL" : "not-tested", result);
        fflush(stdout);
        if (!stat_ok || !sized || (verify && !bytes_ok)) {
            fprintf(stderr, "File integrity check failed at type %" PRIu32 "; stopping this probe.\n", requested);
            result_code = 1;
            break;
        }
        if (requested == 12 && !passed) {
            fprintf(stderr, "Known LZFSE type 12 control failed; stopping this probe.\n");
            result_code = 1;
            break;
        }
    }
    free(sample);
    dlclose(framework);
    alarm(0);

    if (result_code == 0 && !verify) {
        fprintf(stderr, "Write phase complete. No kernel decode claim is possible until detach, read-only reattach, and verification.\n");
    } else if (result_code == 0 && candidates) {
        fprintf(stderr, "%u additional type(s) matched their requested ID and passed readback after remount.\n",
                candidate_hits);
        fprintf(stderr, "This does NOT identify any type as LZRAVEN or LZMESH. Unsupported requests may silently fall back to another codec.\n");
    }
    return result_code;
}
