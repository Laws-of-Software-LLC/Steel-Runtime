#ifndef STEEL_REGION_H
#define STEEL_REGION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct steel_region_block {
  struct steel_region_block *next;
  size_t used;
  size_t capacity;
  uint8_t data[];
} steel_region_block_t;

typedef struct steel_region {
  steel_region_block_t *head;
  size_t default_block_size;
  size_t max_total_bytes;
  size_t total_bytes;
  uint64_t generation;
} steel_region_t;

void steel_region_init(steel_region_t *region, size_t default_block_size);
void steel_region_init_with_limit(steel_region_t *region, size_t default_block_size, size_t max_total_bytes);
void steel_region_reset(steel_region_t *region);
void steel_region_destroy(steel_region_t *region);
void *steel_region_alloc(steel_region_t *region, size_t size, size_t alignment);

#ifdef __cplusplus
}
#endif

#endif
