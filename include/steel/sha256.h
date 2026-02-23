#ifndef STEEL_SHA256_H
#define STEEL_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct steel_sha256_ctx {
  uint32_t state[8];
  uint64_t bit_len;
  uint8_t block[64];
  size_t block_len;
} steel_sha256_ctx_t;

void steel_sha256_init(steel_sha256_ctx_t *ctx);
void steel_sha256_update(steel_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void steel_sha256_final(steel_sha256_ctx_t *ctx, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
