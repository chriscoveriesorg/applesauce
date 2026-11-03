#ifndef APPLESAUCE_FSKIT_BRIDGE_H
#define APPLESAUCE_FSKIT_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct AscfReader AscfReader;
typedef struct AscfInfo {
    uint64_t logical_size;
    uint32_t codec_selector;
    uint32_t reserved;
    uint8_t logical_sha256[32];
} AscfInfo;

/* Zero on success; positive POSIX errno otherwise. The source FD must be
 * O_RDONLY, regular, dedicated to this archive and retained by the caller. */
int32_t ascf_open_fd(int32_t fd, AscfReader **out);
int32_t ascf_info(AscfReader *reader, AscfInfo *out);
/* Logical pread, max 8 MiB. On failure *out_read=0 and buffer unchanged.
 * EOF returns zero read bytes; capacity=0 permits null destination. */
int32_t ascf_pread(AscfReader *reader, uint64_t offset,
                  uint8_t *destination, size_t capacity, size_t *out_read);
/* Full SHA-256 verification is a separate pre-publication gate. */
int32_t ascf_verify_all(AscfReader *reader);
/* Requires all outstanding operations to have completed; close only once. */
void ascf_close(AscfReader *reader);

#ifdef __cplusplus
}
#endif
#endif
