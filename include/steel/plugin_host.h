#ifndef STEEL_PLUGIN_HOST_H
#define STEEL_PLUGIN_HOST_H

#include <stddef.h>
#include <stdint.h>

#include "steel/plugin_manifest.h"
#include "steel/region.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct steel_call {
  steel_facet_id_t facet_id;
  uint32_t method_id;
  uint32_t receiver_handle;
  uint32_t permissions;
  uint8_t *input;
  size_t input_len;
} steel_call_t;

typedef struct steel_bytes_view {
  const uint8_t *ptr;
  size_t len;
} steel_bytes_view_t;

typedef struct steel_typed_value {
  steel_signature_type_t type;
  union {
    char c;
    signed char sc;
    unsigned char uc;
    short s;
    unsigned short us;
    int i;
    unsigned int ui;
    long l;
    unsigned long ul;
    long long ll;
    unsigned long long ull;
    float f;
    double d;
    long double ld;
    uintptr_t ptr;
    uint32_t u32;
    uint8_t boolean;
    steel_bytes_view_t bytes;
  } as;
} steel_typed_value_t;

typedef struct steel_result {
  uint8_t *output;
  size_t output_len;
  steel_region_t storage;
  uint32_t storage_magic;
  int storage_initialized;
} steel_result_t;

typedef struct steel_typed_result {
  steel_result_t raw;
  steel_typed_value_t value;
} steel_typed_result_t;

typedef struct steel_plugin steel_plugin_t;

typedef struct steel_engine_vtable {
  int (*open_component)(steel_plugin_t *plugin, const char *path, char *err, size_t err_len);
  int (*invoke)(steel_plugin_t *plugin,
                const steel_call_t *call,
                steel_result_t *result,
                char *err,
                size_t err_len);
  void (*close)(steel_plugin_t *plugin);
} steel_engine_vtable_t;

struct steel_plugin {
  steel_manifest_t manifest;
  steel_engine_vtable_t engine;
  void *engine_state;
  steel_region_t plugin_region;
  uint32_t plugin_region_allotment_bytes;
  uint32_t granted_permissions;
  uint32_t *facet_granted_permissions;
};

int steel_plugin_load(steel_plugin_t *plugin,
                      const char *path,
                      const steel_policy_t *policy,
                      const steel_engine_vtable_t *engine,
                      char *err,
                      size_t err_len);

int steel_plugin_invoke(steel_plugin_t *plugin,
                        const steel_call_t *call,
                        steel_result_t *result,
                        char *err,
                        size_t err_len);
int steel_plugin_invoke_typed(steel_plugin_t *plugin,
                              const steel_facet_id_t *facet_id,
                              uint32_t method_id,
                              uint32_t receiver_handle,
                              uint32_t permissions,
                              const steel_typed_value_t *args,
                              size_t arg_count,
                              steel_typed_result_t *result,
                              char *err,
                              size_t err_len);

void steel_result_free(steel_result_t *result);
void steel_typed_result_free(steel_typed_result_t *result);
void steel_plugin_unload(steel_plugin_t *plugin);

steel_engine_vtable_t steel_null_engine(void);
steel_engine_vtable_t steel_wasmtime_component_engine(void);

/* Request host input copy-back write after invoke. Does NOT expose direct host memory pointers. */
#define STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK STEEL_PLUGIN_PERM_ALLOW_HOST_INPUT_COPYBACK
/* Backward-compatible alias. */
#define STEEL_CALL_PERM_ALLOW_HOST_MEMORY_WRITE STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK
#define STEEL_CALL_PERM_INPUT_IS_CRITICAL (1u << 30)

#ifdef __cplusplus
}
#endif

#endif
