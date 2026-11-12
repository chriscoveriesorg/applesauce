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
    struct stat after;
    if (fstat(input, &after) || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino || before.st_size != after.st_size) {
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
    int output = open(argv[4], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) {
        perror("opening decoded output");
        free(decoded);
        return 1;
    }
    int failed = exact_write(output, decoded, capacity) || fsync(output);
    if (close(output)) failed = 1;
    free(decoded);
    if (failed) {
        fputs("writing decoded output failed\n", stderr);
        unlink(argv[4]);
        return 1;
    }
    return 0;
}
