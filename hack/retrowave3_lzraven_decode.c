#define _POSIX_C_SOURCE 200809L
#include "lzraven.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CLEAR_BYTES (8u * 1024u * 1024u)

static int exact_read(int fd, unsigned char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int exact_write(int fd, const unsigned char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        offset += (size_t)count;
    }
    return 0;
}

static int parse_capacity(const char *value, size_t *result)
{
    if (!*value) return -1;
    for (const char *p = value; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long capacity = strtoull(value, &end, 10);
    if (errno || !end || *end || !capacity || capacity > MAX_CLEAR_BYTES) return -1;
    *result = (size_t)capacity;
    return 0;
}

static int same_inode(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

/* The input path and opened file must still refer to the same byte snapshot.
 * Inode and size alone permit same-sized rewrites, even with restored mtime.
 * Use the platform's nanosecond timestamps to detect such mutations. */
#if defined(__APPLE__)
#define SNAP_MTIME(st) ((st)->st_mtimespec)
#define SNAP_CTIME(st) ((st)->st_ctimespec)
#else
#define SNAP_MTIME(st) ((st)->st_mtim)
#define SNAP_CTIME(st) ((st)->st_ctim)
#endif

static int same_input_snapshot(const struct stat *a, const struct stat *b)
{
    return S_ISREG(b->st_mode) && same_inode(a, b)
        && a->st_size == b->st_size
        && SNAP_MTIME(a).tv_sec == SNAP_MTIME(b).tv_sec
        && SNAP_MTIME(a).tv_nsec == SNAP_MTIME(b).tv_nsec
        && SNAP_CTIME(a).tv_sec == SNAP_CTIME(b).tv_sec
        && SNAP_CTIME(a).tv_nsec == SNAP_CTIME(b).tv_nsec;
}

/* Stage privately, then publish with atomic, descriptor-relative no-clobber.
 * On any failure after publication, leave the destination for inspection.
 * This does not protect against continuous writers in the output directory. */
static int publish_noclobber(const char *path, const unsigned char *bytes, size_t length)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) {
        fputs("invalid output filename\n", stderr);
        return -1;
    }
    char *parent = slash ? strndup(path, slash == path ? 1 : (size_t)(slash - path))
                         : strdup(".");
    if (!parent) return -1;
    int dir = open(parent, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) {
        perror("opening output parent");
        free(parent);
        return -1;
    }
    struct stat parent_inode;
    if (fstat(dir, &parent_inode) || !S_ISDIR(parent_inode.st_mode)) {
        close(dir);
        free(parent);
        return -1;
    }
    enum { STAGE_PREFIX_LEN = sizeof(".raven-alt-") - 1 };
    char stage_name[STAGE_PREFIX_LEN + 32 + sizeof(".tmp")];
    int stage = -1;
    for (int attempt = 0; attempt < 8; ++attempt) {
        unsigned char random_bytes[16];
        int entropy = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (entropy < 0) break;
        int entropy_error = exact_read(entropy, random_bytes, sizeof(random_bytes));
        if (close(entropy) || entropy_error) break;
        static const char hex[] = "0123456789abcdef";
        memcpy(stage_name, ".raven-alt-", STAGE_PREFIX_LEN);
        for (size_t i = 0; i < sizeof(random_bytes); ++i) {
            stage_name[STAGE_PREFIX_LEN + 2 * i] = hex[random_bytes[i] >> 4];
            stage_name[STAGE_PREFIX_LEN + 2 * i + 1] = hex[random_bytes[i] & 15];
        }
        memcpy(stage_name + STAGE_PREFIX_LEN + 32, ".tmp", sizeof(".tmp"));
        stage = openat(dir, stage_name,
                       O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (stage >= 0 || errno != EEXIST) break;
    }
    if (stage < 0) {
        perror("creating private output stage");
        close(dir);
        free(parent);
        return -1;
    }

    int failed = 0;
    struct stat owned, actual, current_parent;
    int owned_valid = fstat(stage, &owned) == 0 && S_ISREG(owned.st_mode);
    if (!owned_valid) failed = 1;
    if (!failed && (exact_write(stage, bytes, length) || fsync(stage))) failed = 1;
    if (!failed && (fstatat(dir, stage_name, &actual, AT_SYMLINK_NOFOLLOW)
                    || !same_inode(&owned, &actual))) failed = 1;
    if (!failed && (stat(parent, &current_parent)
                    || !same_inode(&parent_inode, &current_parent))) failed = 1;
    if (!failed && linkat(dir, stage_name, dir, name, 0)) failed = 1;
    if (!failed && (fstatat(dir, name, &actual, AT_SYMLINK_NOFOLLOW)
                    || !same_inode(&owned, &actual))) failed = 1;
    if (!failed && (stat(parent, &current_parent)
                    || !same_inode(&parent_inode, &current_parent))) failed = 1;
    if (close(stage)) failed = 1;
    /* An attacker may replace the stage name; preserve any replacement. */
    if (owned_valid && !fstatat(dir, stage_name, &actual, AT_SYMLINK_NOFOLLOW)
        && same_inode(&owned, &actual)) {
        if (unlinkat(dir, stage_name, 0)) failed = 1;
    } else {
        failed = 1;
    }
    if (!failed && fsync(dir)) failed = 1;
    if (close(dir)) failed = 1;
    free(parent);
    if (failed) fputs("atomic decoded output publication failed\n", stderr);
    return failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "--cap") != 0) {
        fputs("usage: raven-alt --cap EXPECTED_BYTES INPUT OUTPUT\n", stderr);
        return 2;
    }
    size_t capacity = 0;
    if (parse_capacity(argv[2], &capacity)) {
        fputs("invalid bounded Raven clear length\n", stderr);
        return 2;
    }
    int input = open(argv[3], O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (input < 0) { perror("opening compressed input"); return 1; }
    struct stat before;
    if (fstat(input, &before) || !S_ISREG(before.st_mode)
        || before.st_size <= 0
        || (uint64_t)before.st_size > (uint64_t)capacity * 2 + 65536) {
        fputs("compressed input is not a bounded regular file\n", stderr);
        close(input);
        return 1;
    }
    size_t encoded_size = (size_t)before.st_size;
    unsigned char *encoded = malloc(encoded_size);
    unsigned char *decoded = malloc(capacity + 1);
    if (!encoded || !decoded) {
        fputs("allocation failure\n", stderr);
        free(encoded); free(decoded); close(input);
        return 1;
    }
    int invalid_input = exact_read(input, encoded, encoded_size);
    struct stat after, path_now;
    if (fstat(input, &after)
        || fstatat(AT_FDCWD, argv[3], &path_now, AT_SYMLINK_NOFOLLOW)
        || !same_input_snapshot(&before, &after)
        || !same_input_snapshot(&before, &path_now)) {
        invalid_input = -1;
    }
    close(input);
    if (invalid_input) {
        fputs("compressed input changed or was truncated\n", stderr);
        free(encoded); free(decoded);
        return 1;
    }
    size_t produced = lzraven_decode_buffer(decoded, capacity + 1, encoded, encoded_size);
    free(encoded);
    if (produced != capacity) {
        fputs("Raven decoder returned a wrong byte count\n", stderr);
        free(decoded);
        return 1;
    }
    int published = publish_noclobber(argv[4], decoded, capacity);
    free(decoded);
    return published ? 1 : 0;
}
