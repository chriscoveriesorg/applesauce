/*
 * Probe the AppleFSCompression private API on a DISPOSABLE APFS volume only.
 *
 * Apple's Compression.framework algorithm values are unrelated to the
 * decmpfs filesystem type IDs. We use the filesystem's own compressor API
 * to ask for a handful of candidate IDs; we never craft arbitrary xattrs.
 *
 * Interface signatures are based on Siguza/fscmp's reverse-engineered
 * AppleFSCompression header (MIT). Apple may change the private ABI.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
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
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    bool valid = true;
    size_t offset = 0;
    while (offset < size) {
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
    close(fd);
    return valid;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: apfs-type-probe /path/to/disposable/apfs/mount\n");
        return 2;
    }

    struct statfs volume;
    if (statfs(argv[1], &volume) != 0 || strcmp(volume.f_fstypename, "apfs") != 0) {
        fprintf(stderr, "Refusing to run: the probe mount must be APFS.\n");
        return 2;
    }
    if (strcmp(volume.f_mntonname, argv[1]) != 0 ||
        strstr(volume.f_mntonname, "applesauce-probe") == NULL) {
        fprintf(stderr, "Refusing to run outside a dedicated applesauce-probe APFS mount.\n");
        return 2;
    }
    char marker_path[1024];
    int marker_len = snprintf(marker_path, sizeof(marker_path), "%s/.applesauce-disposable-image", argv[1]);
    if (marker_len < 0 || (size_t)marker_len >= sizeof(marker_path) ||
        access(marker_path, R_OK) != 0) {
        fprintf(stderr, "Refusing to run without the disposable test-image marker.\n");
        return 2;
    }

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
    if (!create_queue || !compress_file || !finish_queue || !query_type) {
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

    /* 12 = known LZFSE, 14 = known LZBitmap; 15..22 are unverified candidates. */
    const uint32_t types[] = {12, 14, 15, 16, 17, 18, 19, 20, 21, 22};
    puts("| Requested type | API accepted | Stored type | `UF_COMPRESSED` | Readback | Disk bytes | Result |");
    puts("| ---: | :---: | ---: | :---: | :---: | ---: | --- |");

    unsigned int candidate_hits = 0;
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i) {
        uint32_t requested = types[i];
        char path[1024];
        int len = snprintf(path, sizeof(path), "%s/type-%u.jsonl", argv[1], requested);
        if (len < 0 || (size_t)len >= sizeof(path)) {
            fprintf(stderr, "Probe path too long.\n");
            free(sample);
            dlclose(framework);
            return 2;
        }

        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        bool wrote = fd >= 0 && write_all(fd, sample, SAMPLE_SIZE);
        bool closed = fd >= 0 && close(fd) == 0;
        if (!wrote || !closed) {
            fprintf(stderr, "Cannot write sample on test image (type %u): %s\n", requested, strerror(errno));
            free(sample);
            dlclose(framework);
            return 2;
        }

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
            free(sample);
            dlclose(framework);
            return 2;
        }
        CFDictionarySetValue(options, CFSTR("CompressionTypes"), type_string);
        CFDictionarySetValue(options, CFSTR("CompressionLevel"), level_number);
        CFRelease(type_string);
        CFRelease(level_number);

        void *queue = create_queue(NULL, NULL, NULL, NULL, options);
        bool accepted = queue && compress_file(queue, path, NULL);
        if (queue) finish_queue(queue);
        CFRelease(options);

        uint32_t stored = 0;
        bool queried = query_type(path, &stored) == 0;
        struct stat st;
        bool stat_ok = stat(path, &st) == 0;
        bool flagged = stat_ok && (st.st_flags & UF_COMPRESSED) != 0;
        bool bytes_ok = verify_file(path, sample, SAMPLE_SIZE);
        bool transparent = accepted && queried && stored == requested && flagged && bytes_ok;
        if (requested >= 15 && transparent) ++candidate_hits;

        const char *result = transparent ? "**transparent**" :
                             !bytes_ok ? "READ FAILURE" :
                             queried && stored != 0 && stored != requested ? "different type stored" :
                             "uncompressed / unsupported";
        printf("| %u | %s | %u | %s | %s | %lld | %s |\n",
               requested, accepted ? "yes" : "no", queried ? stored : 0,
               flagged ? "yes" : "no", bytes_ok ? "OK" : "FAIL",
               stat_ok ? (long long)st.st_blocks * 512LL : -1LL, result);
        if (!bytes_ok) {
            fprintf(stderr, "Readback failed at type %u; stopping this probe.\n", requested);
            free(sample);
            dlclose(framework);
            return 1;
        }
        if (requested == 12 && !transparent) {
            fprintf(stderr, "Known LZFSE type 12 failed; stopping before testing unknown types.\n");
            free(sample);
            dlclose(framework);
            return 1;
        }
    }
    free(sample);
    dlclose(framework);

    if (candidate_hits == 0) {
        puts("\n**Finding:** None of the tested IDs 15–22 demonstrated transparent compression on this macOS build.");
    } else {
        printf("\n**Finding:** %u new candidate type(s) passed transparent readback. Their codec identity needs separate verification.\n",
               candidate_hits);
    }
    return 0;
}
