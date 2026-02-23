#include "steel/sha256.h"

#include <string.h>

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROR32((x), 2) ^ ROR32((x), 13) ^ ROR32((x), 22))
#define BSIG1(x) (ROR32((x), 6) ^ ROR32((x), 11) ^ ROR32((x), 25))
#define SSIG0(x) (ROR32((x), 7) ^ ROR32((x), 18) ^ ((x) >> 3))
#define SSIG1(x) (ROR32((x), 17) ^ ROR32((x), 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static void transform(steel_sha256_ctx_t *ctx, const uint8_t block[64]) {
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h;
  uint32_t t1, t2;
  size_t i;

  for (i = 0; i < 16; ++i) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
  }
  for (i = 16; i < 64; ++i) {
    w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
    t2 = BSIG0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void steel_sha256_init(steel_sha256_ctx_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
}

void steel_sha256_update(steel_sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
  size_t i;
  for (i = 0; i < len; ++i) {
    ctx->block[ctx->block_len++] = data[i];
    if (ctx->block_len == 64) {
      transform(ctx, ctx->block);
      ctx->bit_len += 512;
      ctx->block_len = 0;
    }
  }
}

void steel_sha256_final(steel_sha256_ctx_t *ctx, uint8_t out[32]) {
  size_t i;
  uint64_t bit_len = ctx->bit_len + (uint64_t)ctx->block_len * 8u;

  ctx->block[ctx->block_len++] = 0x80;
  if (ctx->block_len > 56) {
    while (ctx->block_len < 64) {
      ctx->block[ctx->block_len++] = 0x00;
    }
    transform(ctx, ctx->block);
    ctx->block_len = 0;
  }
  while (ctx->block_len < 56) {
    ctx->block[ctx->block_len++] = 0x00;
  }
  for (i = 0; i < 8; ++i) {
    ctx->block[63 - i] = (uint8_t)(bit_len >> (i * 8));
  }
  transform(ctx, ctx->block);

  for (i = 0; i < 8; ++i) {
    out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
    out[i * 4 + 3] = (uint8_t)ctx->state[i];
  }
}
