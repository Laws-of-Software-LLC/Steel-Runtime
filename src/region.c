#include "steel/region.h"

#include <stdlib.h>
#include <string.h>

enum {
  STEEL_REGION_MIN_BLOCK = 1024
};

static size_t align_up(size_t value, size_t alignment) {
  size_t mask;
  if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
    alignment = sizeof(void *);
  }
  mask = alignment - 1;
  return (value + mask) & ~mask;
}

static steel_region_block_t *region_new_block(size_t capacity) {
  steel_region_block_t *blk;
  blk = (steel_region_block_t *)malloc(sizeof(*blk) + capacity);
  if (blk == NULL) {
    return NULL;
  }
  blk->next = NULL;
  blk->used = 0;
  blk->capacity = capacity;
  return blk;
}

void steel_region_init(steel_region_t *region, size_t default_block_size) {
  steel_region_init_with_limit(region, default_block_size, 0);
}

void steel_region_init_with_limit(steel_region_t *region, size_t default_block_size, size_t max_total_bytes) {
  if (region == NULL) {
    return;
  }
  memset(region, 0, sizeof(*region));
  if (default_block_size < STEEL_REGION_MIN_BLOCK) {
    default_block_size = STEEL_REGION_MIN_BLOCK;
  }
  region->default_block_size = default_block_size;
  region->max_total_bytes = max_total_bytes;
}

void steel_region_reset(steel_region_t *region) {
  steel_region_block_t *blk;
  steel_region_block_t *next;
  if (region == NULL) {
    return;
  }
  blk = region->head;
  while (blk != NULL) {
    next = blk->next;
    free(blk);
    blk = next;
  }
  region->head = NULL;
  region->total_bytes = 0;
  region->generation++;
}

void steel_region_destroy(steel_region_t *region) { steel_region_reset(region); }

void *steel_region_alloc(steel_region_t *region, size_t size, size_t alignment) {
  steel_region_block_t *blk;
  size_t offset;
  size_t needed;
  size_t capacity;

  if (region == NULL || size == 0) {
    return NULL;
  }

  blk = region->head;
  if (blk != NULL) {
    offset = align_up(blk->used, alignment);
    if (offset <= blk->capacity && size <= blk->capacity - offset) {
      void *ptr = &blk->data[offset];
      blk->used = offset + size;
      return ptr;
    }
  }

  needed = align_up(size, alignment);
  capacity = region->default_block_size;
  if (capacity < needed) {
    capacity = needed;
  }
  if (region->max_total_bytes > 0) {
    size_t remaining;
    if (region->total_bytes >= region->max_total_bytes) {
      return NULL;
    }
    remaining = region->max_total_bytes - region->total_bytes;
    if (needed > remaining) {
      return NULL;
    }
    if (capacity > remaining) {
      capacity = remaining;
    }
  }

  blk = region_new_block(capacity);
  if (blk == NULL) {
    return NULL;
  }
  blk->next = region->head;
  region->head = blk;
  region->total_bytes += capacity;

  offset = align_up(blk->used, alignment);
  if (offset > blk->capacity || size > blk->capacity - offset) {
    return NULL;
  }
  blk->used = offset + size;
  return &blk->data[offset];
}
