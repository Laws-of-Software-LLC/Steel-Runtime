#ifndef STEEL_PLUGIN_MANIFEST_H
#define STEEL_PLUGIN_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#include "steel/facet.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STEEL_MANIFEST_SECTION_NAME "steel.manifest.v1"
#define STEEL_MANIFEST_MAGIC 0x4D504653u /* 'SFPM' in canonical manifest wire encoding */
#define STEEL_HOST_ABI_MAJOR 1u
#define STEEL_DEFAULT_PLUGIN_REGION_BYTES 4096u
/* Allows post-invoke copy-back into host input buffer. Does NOT grant direct host-memory access. */
#define STEEL_PLUGIN_PERM_ALLOW_HOST_INPUT_COPYBACK (1u << 0)
/* Backward-compatible alias. */
#define STEEL_PLUGIN_PERM_ALLOW_HOST_MEMORY_WRITE STEEL_PLUGIN_PERM_ALLOW_HOST_INPUT_COPYBACK
#define STEEL_PLUGIN_KNOWN_PERMISSIONS (STEEL_PLUGIN_PERM_ALLOW_HOST_INPUT_COPYBACK)

typedef struct steel_manifest_method {
  uint32_t facet_index;
  uint32_t method_id;
  uint16_t param_count;
  uint16_t reserved;
  uint64_t signature_type_hash;
  steel_fun_signature_t steel_fun_signature;
} steel_manifest_method_t;

typedef struct steel_manifest_facet {
  const uint8_t *id_bytes;
  uint32_t method_start;
  uint32_t method_count;
  uint32_t requested_permissions;
} steel_manifest_facet_t;

typedef struct steel_manifest_object_type {
  const char *name;
  uint16_t name_len;
  uint16_t facet_count;
  uint16_t reserved;
  uint32_t *facet_indices;
} steel_manifest_object_type_t;

typedef struct steel_manifest {
  uint32_t magic;
  uint16_t abi_major;
  uint16_t abi_minor;
  uint64_t host_layout_hash;
  uint64_t type_table_hash;
  uint32_t memory_min_pages;
  uint32_t memory_max_pages;
  uint32_t requested_permissions;
  uint32_t requested_region_bytes;
  uint32_t facet_count;
  uint32_t method_count;
  uint32_t object_type_count;

  steel_manifest_facet_t *facets;
  steel_manifest_method_t *methods;
  steel_manifest_object_type_t *object_types;
  uint8_t component_sha256[32];
  const char *signer_id;
  uint16_t signer_id_len;
  const uint8_t *signature;
  uint16_t signature_len;
  const uint8_t *signed_payload;
  size_t signed_payload_len;
  uint8_t *owned_component_bytes;
  size_t owned_component_len;
} steel_manifest_t;

typedef struct steel_facet_permission_rule {
  steel_facet_id_t facet_id;
  uint32_t allowed_permissions;
} steel_facet_permission_rule_t;

typedef struct steel_permission_rule {
  const char *signer_id;
  const char *host_user_id;
  uint32_t allowed_permissions;
  const steel_facet_permission_rule_t *facet_permissions;
  size_t facet_permission_count;
} steel_permission_rule_t;

typedef struct steel_policy {
  const char *host_user_id;
  uint64_t expected_layout_hash;
  uint64_t expected_type_table_hash;
  uint32_t min_abi_minor;
  uint32_t max_memory_pages;
  uint32_t default_plugin_region_bytes;
  uint32_t max_plugin_region_bytes;
  uint32_t allowed_plugin_permissions;
  const char *trusted_attestation_public_key_path;
  const char *required_signer_id;
  const steel_permission_rule_t *permission_rules;
  size_t permission_rule_count;
} steel_policy_t;

int steel_extract_manifest_from_component(const uint8_t *wasm_bytes,
                                          size_t wasm_len,
                                          steel_manifest_t *out_manifest,
                                          char *err,
                                          size_t err_len);

int steel_verify_manifest(const steel_manifest_t *manifest,
                          const steel_policy_t *policy,
                          char *err,
                          size_t err_len);

void steel_manifest_free(steel_manifest_t *manifest);

#ifdef __cplusplus
}
#endif

#endif
