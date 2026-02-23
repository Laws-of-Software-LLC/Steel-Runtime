#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "steel/plugin_manifest.h"
#include "steel/sha256.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_err(char *err, size_t err_len, const char *fmt, ...) {
  va_list ap;
  if (err == NULL || err_len == 0) {
    return;
  }
  va_start(ap, fmt);
  (void)vsnprintf(err, err_len, fmt, ap);
  va_end(ap);
}

static int read_u16_wire(const uint8_t **cursor, const uint8_t *end, uint16_t *out) {
  const uint8_t *p = *cursor;
  if ((size_t)(end - p) < 2) {
    return -1;
  }
  *out = (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
  *cursor = p + 2;
  return 0;
}

static int read_u32_wire(const uint8_t **cursor, const uint8_t *end, uint32_t *out) {
  const uint8_t *p = *cursor;
  if ((size_t)(end - p) < 4) {
    return -1;
  }
  *out = ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  *cursor = p + 4;
  return 0;
}

static int read_u64_wire(const uint8_t **cursor, const uint8_t *end, uint64_t *out) {
  const uint8_t *p = *cursor;
  if ((size_t)(end - p) < 8) {
    return -1;
  }
  *out = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
  *cursor = p + 8;
  return 0;
}

static int read_uleb128(const uint8_t **cursor, const uint8_t *end, uint32_t *out) {
  uint32_t value = 0;
  uint32_t shift = 0;
  const uint8_t *p = *cursor;

  while (p < end && shift < 35) {
    uint8_t byte = *p++;
    value |= (uint32_t)(byte & 0x7F) << shift;
    if ((byte & 0x80) == 0) {
      *cursor = p;
      *out = value;
      return 0;
    }
    shift += 7;
  }

  return -1;
}

static int verify_signature_with_libcrypto(const steel_manifest_t *manifest,
                                           const char *public_key_path,
                                           char *err,
                                           size_t err_len) {
  FILE *pubkey_file = NULL;
  EVP_PKEY *pubkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  int ok = 0;

  pubkey_file = fopen(public_key_path, "rb");
  if (pubkey_file == NULL) {
    write_err(err, err_len, "failed to open public key");
    goto cleanup;
  }

  pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
  fclose(pubkey_file);
  pubkey_file = NULL;
  if (pubkey == NULL) {
    write_err(err, err_len, "failed to parse public key");
    goto cleanup;
  }

  md_ctx = EVP_MD_CTX_new();
  if (md_ctx == NULL) {
    write_err(err, err_len, "failed to allocate crypto context");
    goto cleanup;
  }

  if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
    write_err(err, err_len, "failed to initialize signature verification");
    goto cleanup;
  }
  if (EVP_DigestVerifyUpdate(md_ctx, manifest->signed_payload, manifest->signed_payload_len) != 1) {
    write_err(err, err_len, "failed to process signature payload");
    goto cleanup;
  }
  if (EVP_DigestVerifyFinal(md_ctx, manifest->signature, manifest->signature_len) != 1) {
    write_err(err, err_len, "manifest signature verification failed");
    goto cleanup;
  }

  ok = 1;

cleanup:
  if (pubkey_file != NULL) {
    fclose(pubkey_file);
  }
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pubkey);
  return ok ? 0 : -1;
}

static int parse_manifest_payload(const uint8_t *payload,
                                  size_t payload_len,
                                  steel_manifest_t *out_manifest,
                                  char *err,
                                  size_t err_len) {
  const uint8_t *p = payload;
  const uint8_t *end = payload + payload_len;
  uint32_t magic = 0;
  uint32_t facet_count = 0;
  uint32_t method_count = 0;
  uint32_t object_type_count = 0;
  size_t i;

  memset(out_manifest, 0, sizeof(*out_manifest));

  if (read_u32_wire(&p, end, &magic) != 0) {
    write_err(err, err_len, "manifest header truncated");
    return -1;
  }
  out_manifest->magic = magic;

  if (read_u16_wire(&p, end, &out_manifest->abi_major) != 0 || read_u16_wire(&p, end, &out_manifest->abi_minor) != 0) {
    write_err(err, err_len, "manifest ABI version truncated");
    return -1;
  }

  if (read_u64_wire(&p, end, &out_manifest->host_layout_hash) != 0 ||
      read_u64_wire(&p, end, &out_manifest->type_table_hash) != 0) {
    write_err(err, err_len, "manifest hashes truncated");
    return -1;
  }

  if (read_u32_wire(&p, end, &out_manifest->memory_min_pages) != 0 ||
      read_u32_wire(&p, end, &out_manifest->memory_max_pages) != 0 ||
      read_u32_wire(&p, end, &out_manifest->requested_permissions) != 0 ||
      read_u32_wire(&p, end, &out_manifest->requested_region_bytes) != 0 || read_u32_wire(&p, end, &facet_count) != 0 ||
      read_u32_wire(&p, end, &method_count) != 0 || read_u32_wire(&p, end, &object_type_count) != 0) {
    write_err(err, err_len, "manifest counts truncated");
    return -1;
  }
  out_manifest->facet_count = facet_count;
  out_manifest->method_count = method_count;
  out_manifest->object_type_count = object_type_count;

  if (facet_count > 10000 || method_count > 100000 || object_type_count > 10000) {
    write_err(err, err_len, "manifest count exceeds policy bounds");
    return -1;
  }

  if (facet_count > 0) {
    out_manifest->facets = (steel_manifest_facet_t *)calloc(facet_count, sizeof(*out_manifest->facets));
    if (out_manifest->facets == NULL) {
      write_err(err, err_len, "manifest facet allocation failed");
      return -1;
    }
  }

  if (method_count > 0) {
    out_manifest->methods =
        (steel_manifest_method_t *)calloc(method_count, sizeof(*out_manifest->methods));
    if (out_manifest->methods == NULL) {
      write_err(err, err_len, "manifest method allocation failed");
      return -1;
    }
  }
  if (object_type_count > 0) {
    out_manifest->object_types =
        (steel_manifest_object_type_t *)calloc(object_type_count, sizeof(*out_manifest->object_types));
    if (out_manifest->object_types == NULL) {
      write_err(err, err_len, "manifest object type allocation failed");
      return -1;
    }
  }

  for (i = 0; i < facet_count; ++i) {
    steel_manifest_facet_t *facet = &out_manifest->facets[i];
    if ((size_t)(end - p) < 28) {
      write_err(err, err_len, "manifest facet table truncated at %zu", i);
      return -1;
    }
    facet->id_bytes = p;
    p += 16;
    if (read_u32_wire(&p, end, &facet->method_start) != 0 || read_u32_wire(&p, end, &facet->method_count) != 0 ||
        read_u32_wire(&p, end, &facet->requested_permissions) != 0) {
      write_err(err, err_len, "manifest facet entry malformed at %zu", i);
      return -1;
    }
  }

  for (i = 0; i < method_count; ++i) {
    steel_manifest_method_t *method = &out_manifest->methods[i];
    size_t j;
    if ((size_t)(end - p) < 16) {
      write_err(err, err_len, "manifest method table truncated at %zu", i);
      return -1;
    }
    if (read_u32_wire(&p, end, &method->facet_index) != 0 || read_u32_wire(&p, end, &method->method_id) != 0) {
      write_err(err, err_len, "manifest method entry malformed at %zu", i);
      return -1;
    }
    if (read_u16_wire(&p, end, &method->param_count) != 0 || read_u16_wire(&p, end, &method->reserved) != 0) {
      write_err(err, err_len, "manifest signature header malformed at %zu", i);
      return -1;
    }
    if (read_u64_wire(&p, end, &method->signature_type_hash) != 0) {
      write_err(err, err_len, "manifest signature hash truncated at %zu", i);
      return -1;
    }
    if ((size_t)(end - p) < ((size_t)method->param_count * sizeof(uint16_t)) + sizeof(uint16_t)) {
      write_err(err, err_len, "manifest typed signature truncated at %zu", i);
      return -1;
    }
    if (method->param_count > 0) {
      steel_signature_type_t *param_types =
          (steel_signature_type_t *)calloc(method->param_count, sizeof(steel_signature_type_t));
      if (param_types == NULL) {
        write_err(err, err_len, "manifest param type allocation failed at %zu", i);
        return -1;
      }
      for (j = 0; j < method->param_count; ++j) {
        uint16_t t = 0;
        if (read_u16_wire(&p, end, &t) != 0) {
          free(param_types);
          write_err(err, err_len, "manifest param type malformed at method[%zu] param[%zu]", i, j);
          return -1;
        }
        param_types[j] = (steel_signature_type_t)t;
      }
      method->steel_fun_signature.param_types = param_types;
      method->steel_fun_signature.param_count = method->param_count;
    }
    {
      uint16_t result_type = 0;
      if (read_u16_wire(&p, end, &result_type) != 0) {
        write_err(err, err_len, "manifest result type malformed at %zu", i);
        return -1;
      }
      method->steel_fun_signature.result_type = (steel_signature_type_t)result_type;
    }
    if (steel_signature_validate(&method->steel_fun_signature) != 0) {
      write_err(err, err_len, "manifest typed signature invalid at %zu", i);
      return -1;
    }
  }

  for (i = 0; i < object_type_count; ++i) {
    uint16_t name_len = 0;
    uint16_t facet_count = 0;
    size_t j;
    if (read_u16_wire(&p, end, &name_len) != 0) {
      write_err(err, err_len, "manifest object type length malformed at %zu", i);
      return -1;
    }
    if (name_len == 0) {
      write_err(err, err_len, "manifest object type name empty at %zu", i);
      return -1;
    }
    if ((size_t)(end - p) < name_len) {
      write_err(err, err_len, "manifest object type name truncated at %zu", i);
      return -1;
    }
    out_manifest->object_types[i].name = (const char *)p;
    out_manifest->object_types[i].name_len = name_len;
    p += name_len;
    if (read_u16_wire(&p, end, &facet_count) != 0) {
      write_err(err, err_len, "manifest object facet count malformed at %zu", i);
      return -1;
    }
    out_manifest->object_types[i].facet_count = facet_count;
    if (facet_count > 0) {
      out_manifest->object_types[i].facet_indices = (uint32_t *)calloc(facet_count, sizeof(uint32_t));
      if (out_manifest->object_types[i].facet_indices == NULL) {
        write_err(err, err_len, "manifest object facet index allocation failed at %zu", i);
        return -1;
      }
      for (j = 0; j < facet_count; ++j) {
        if (read_u32_wire(&p, end, &out_manifest->object_types[i].facet_indices[j]) != 0) {
          write_err(err, err_len, "manifest object facet index malformed at object[%zu] facet[%zu]", i, j);
          return -1;
        }
      }
    }
  }

  if ((size_t)(end - p) < 34) {
    write_err(err, err_len, "manifest attestation block truncated");
    return -1;
  }
  memcpy(out_manifest->component_sha256, p, 32);
  p += 32;

  if (read_u16_wire(&p, end, &out_manifest->signer_id_len) != 0) {
    write_err(err, err_len, "manifest signer id length truncated");
    return -1;
  }
  if ((size_t)(end - p) < out_manifest->signer_id_len) {
    write_err(err, err_len, "manifest signer id truncated");
    return -1;
  }
  out_manifest->signer_id = (const char *)p;
  p += out_manifest->signer_id_len;

  out_manifest->signed_payload_len = (size_t)(p - payload);
  out_manifest->signed_payload = payload;

  if (read_u16_wire(&p, end, &out_manifest->signature_len) != 0) {
    write_err(err, err_len, "manifest signature length truncated");
    return -1;
  }
  if ((size_t)(end - p) < out_manifest->signature_len) {
    write_err(err, err_len, "manifest signature truncated");
    return -1;
  }
  out_manifest->signature = p;
  p += out_manifest->signature_len;

  if (p != end) {
    write_err(err, err_len, "manifest payload has %zu trailing bytes", (size_t)(end - p));
    return -1;
  }

  return 0;
}

int steel_extract_manifest_from_component(const uint8_t *wasm_bytes,
                                          size_t wasm_len,
                                          steel_manifest_t *out_manifest,
                                          char *err,
                                          size_t err_len) {
  const uint8_t wasm_magic[] = {0x00, 0x61, 0x73, 0x6D};
  const uint8_t *p = wasm_bytes;
  const uint8_t *end = wasm_bytes + wasm_len;
  steel_sha256_ctx_t hash_ctx;
  uint8_t digest[32];
  int found_manifest = 0;

  if (wasm_bytes == NULL || out_manifest == NULL || wasm_len < 8) {
    write_err(err, err_len, "invalid component bytes");
    return -1;
  }

  if (memcmp(p, wasm_magic, sizeof(wasm_magic)) != 0) {
    write_err(err, err_len, "not a WebAssembly binary");
    return -1;
  }

  steel_sha256_init(&hash_ctx);
  steel_sha256_update(&hash_ctx, wasm_bytes, 8);

  /* Version 0x0a 0x00 0x01 0x00 is component model; we accept any for forward compatibility. */
  p += 8;

  while (p < end) {
    const uint8_t *section_start = p;
    uint8_t section_id;
    uint32_t section_size = 0;
    const uint8_t *section_payload;
    const uint8_t *section_end;

    section_id = *p++;
    if (read_uleb128(&p, end, &section_size) != 0) {
      write_err(err, err_len, "invalid section length LEB128");
      return -1;
    }
    if ((size_t)(end - p) < section_size) {
      write_err(err, err_len, "section overruns file");
      return -1;
    }

    section_payload = p;
    section_end = p + section_size;

    if (section_id == 0) {
      uint32_t name_len = 0;
      const uint8_t *name_ptr;
      const uint8_t *payload_ptr;
      size_t payload_len;

      if (read_uleb128(&section_payload, section_end, &name_len) != 0) {
        write_err(err, err_len, "custom section name length malformed");
        return -1;
      }
      if ((size_t)(section_end - section_payload) < name_len) {
        write_err(err, err_len, "custom section name truncated");
        return -1;
      }

      name_ptr = section_payload;
      payload_ptr = section_payload + name_len;
      payload_len = (size_t)(section_end - payload_ptr);

      if (name_len == strlen(STEEL_MANIFEST_SECTION_NAME) &&
          memcmp(name_ptr, STEEL_MANIFEST_SECTION_NAME, name_len) == 0) {
        if (parse_manifest_payload(payload_ptr, payload_len, out_manifest, err, err_len) != 0) {
          return -1;
        }
        found_manifest = 1;
        p = section_end;
        continue;
      }
    }

    steel_sha256_update(&hash_ctx, section_start, (size_t)(section_end - section_start));
    p = section_end;
  }

  if (!found_manifest) {
    write_err(err, err_len, "custom section '%s' not found", STEEL_MANIFEST_SECTION_NAME);
    return -1;
  }

  steel_sha256_final(&hash_ctx, digest);
  if (memcmp(digest, out_manifest->component_sha256, sizeof(digest)) != 0) {
    write_err(err, err_len, "component hash mismatch in attestation");
    return -1;
  }
  return 0;
}

int steel_verify_manifest(const steel_manifest_t *manifest,
                          const steel_policy_t *policy,
                          char *err,
                          size_t err_len) {
  size_t i;
  uint32_t default_region_bytes;
  uint32_t effective_region_bytes;

  if (manifest == NULL || policy == NULL) {
    write_err(err, err_len, "manifest/policy missing");
    return -1;
  }

  if (manifest->magic != STEEL_MANIFEST_MAGIC) {
    write_err(err, err_len, "manifest magic mismatch");
    return -1;
  }

  if (manifest->abi_major != STEEL_HOST_ABI_MAJOR) {
    write_err(err, err_len, "ABI major mismatch: host=%u plugin=%u", STEEL_HOST_ABI_MAJOR, manifest->abi_major);
    return -1;
  }

  if (manifest->abi_minor < policy->min_abi_minor) {
    write_err(err, err_len, "ABI minor too old: min=%u plugin=%u", policy->min_abi_minor, manifest->abi_minor);
    return -1;
  }

  if (manifest->host_layout_hash != policy->expected_layout_hash) {
    write_err(err, err_len, "layout hash mismatch");
    return -1;
  }

  if (manifest->type_table_hash != policy->expected_type_table_hash) {
    write_err(err, err_len, "type table hash mismatch");
    return -1;
  }

  if (manifest->memory_min_pages > manifest->memory_max_pages) {
    write_err(err, err_len, "invalid memory bounds: min=%u max=%u", manifest->memory_min_pages,
              manifest->memory_max_pages);
    return -1;
  }

  if (manifest->memory_max_pages > policy->max_memory_pages) {
    write_err(err, err_len, "memory max pages exceeds host policy: policy=%u plugin=%u", policy->max_memory_pages,
              manifest->memory_max_pages);
    return -1;
  }

  if ((manifest->requested_permissions & ~STEEL_PLUGIN_KNOWN_PERMISSIONS) != 0) {
    write_err(err, err_len, "plugin requests unknown permissions mask=0x%x", manifest->requested_permissions);
    return -1;
  }

  default_region_bytes = policy->default_plugin_region_bytes > 0 ? policy->default_plugin_region_bytes
                                                                  : STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  effective_region_bytes =
      manifest->requested_region_bytes > 0 ? manifest->requested_region_bytes : default_region_bytes;
  if (policy->max_plugin_region_bytes > 0 && default_region_bytes > policy->max_plugin_region_bytes) {
    write_err(err, err_len, "host default plugin region exceeds host max policy");
    return -1;
  }
  if (policy->max_plugin_region_bytes > 0 && effective_region_bytes > policy->max_plugin_region_bytes) {
    write_err(err,
              err_len,
              "plugin requested region exceeds host policy: policy=%u plugin=%u",
              policy->max_plugin_region_bytes,
              effective_region_bytes);
    return -1;
  }

  if (manifest->signer_id == NULL || manifest->signer_id_len == 0) {
    write_err(err, err_len, "manifest signer id missing");
    return -1;
  }
  if (manifest->signature == NULL || manifest->signature_len == 0 || manifest->signed_payload == NULL ||
      manifest->signed_payload_len == 0) {
    write_err(err, err_len, "manifest signature payload missing");
    return -1;
  }
  if (policy->required_signer_id != NULL) {
    size_t required_len = strlen(policy->required_signer_id);
    if (required_len != manifest->signer_id_len ||
        memcmp(policy->required_signer_id, manifest->signer_id, manifest->signer_id_len) != 0) {
      write_err(err, err_len, "manifest signer id mismatch");
      return -1;
    }
  }
  if (policy->trusted_attestation_public_key_path == NULL) {
    write_err(err, err_len, "host trusted attestation key path not configured");
    return -1;
  }
  if (verify_signature_with_libcrypto(manifest, policy->trusted_attestation_public_key_path, err, err_len) != 0) {
    return -1;
  }

  for (i = 0; i < manifest->facet_count; ++i) {
    const steel_manifest_facet_t *facet = &manifest->facets[i];
    uint64_t limit = (uint64_t)facet->method_start + (uint64_t)facet->method_count;
    if (limit > manifest->method_count) {
      write_err(err, err_len, "facet[%zu] method range out of bounds", i);
      return -1;
    }
    if ((facet->requested_permissions & ~STEEL_PLUGIN_KNOWN_PERMISSIONS) != 0) {
      write_err(err, err_len, "facet[%zu] requests unknown permissions mask=0x%x", i, facet->requested_permissions);
      return -1;
    }
  }

  for (i = 0; i < manifest->method_count; ++i) {
    const steel_manifest_method_t *method = &manifest->methods[i];
    const steel_manifest_facet_t *facet;
    const steel_vtable_entry_t *contract;

    if (method->facet_index >= manifest->facet_count) {
      write_err(err, err_len, "method[%zu] facet index out of bounds", i);
      return -1;
    }

    facet = &manifest->facets[method->facet_index];
    contract = steel_contract_find_by_facet_bytes(facet->id_bytes, method->method_id);
    if (contract == NULL) {
      write_err(err, err_len, "method[%zu] facet+method not recognized by host", i);
      return -1;
    }

    if (steel_signature_validate(&contract->steel_fun_signature) != 0) {
      write_err(err, err_len, "host typed signature invalid for method[%zu]", i);
      return -1;
    }

    if (steel_signature_validate(&method->steel_fun_signature) != 0) {
      write_err(err, err_len, "manifest typed signature invalid for method[%zu]", i);
      return -1;
    }

    if (!steel_signature_equal(&contract->steel_fun_signature, &method->steel_fun_signature)) {
      write_err(err, err_len, "method[%zu] typed Steel function signature mismatch", i);
      return -1;
    }

    if (steel_signature_type_hash64(&method->steel_fun_signature) != method->signature_type_hash) {
      write_err(err, err_len, "method[%zu] typed signature hash mismatch", i);
      return -1;
    }

    if (steel_signature_type_hash64(&contract->steel_fun_signature) != method->signature_type_hash) {
      write_err(err, err_len, "method[%zu] host typed signature hash mismatch", i);
      return -1;
    }
  }

  for (i = 0; i < manifest->object_type_count; ++i) {
    size_t j;
    const steel_manifest_object_type_t *obj = &manifest->object_types[i];
    if (obj->name == NULL || obj->name_len == 0) {
      write_err(err, err_len, "manifest object type[%zu] missing name", i);
      return -1;
    }
    for (j = i + 1; j < manifest->object_type_count; ++j) {
      const steel_manifest_object_type_t *other = &manifest->object_types[j];
      if (obj->name_len == other->name_len && memcmp(obj->name, other->name, obj->name_len) == 0) {
        write_err(err, err_len, "manifest object type names must be unique");
        return -1;
      }
    }
    for (j = 0; j < obj->facet_count; ++j) {
      if (obj->facet_indices == NULL || obj->facet_indices[j] >= manifest->facet_count) {
        write_err(err, err_len, "manifest object type facet index out of bounds");
        return -1;
      }
    }
  }

  return 0;
}

void steel_manifest_free(steel_manifest_t *manifest) {
  if (manifest == NULL) {
    return;
  }
  if (manifest->methods != NULL) {
    size_t i;
    for (i = 0; i < manifest->method_count; ++i) {
      steel_signature_free(&manifest->methods[i].steel_fun_signature);
    }
  }
  if (manifest->object_types != NULL) {
    size_t i;
    for (i = 0; i < manifest->object_type_count; ++i) {
      free(manifest->object_types[i].facet_indices);
    }
  }
  free(manifest->facets);
  free(manifest->methods);
  free(manifest->object_types);
  free(manifest->owned_component_bytes);
  memset(manifest, 0, sizeof(*manifest));
}
