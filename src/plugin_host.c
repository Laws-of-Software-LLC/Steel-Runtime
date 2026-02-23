#include "steel/plugin_host.h"
#include "steel/contracts_builtin.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if defined(__unix__) || defined(__APPLE__)
#include <pwd.h>
#endif

static void write_err(char *err, size_t err_len, const char *fmt, ...) {
  va_list ap;
  if (err == NULL || err_len == 0) {
    return;
  }
  va_start(ap, fmt);
  (void)vsnprintf(err, err_len, fmt, ap);
  va_end(ap);
}

enum {
  STEEL_RESULT_STORAGE_MAGIC = 0x53524c54u /* SRLT */
};

static int read_file(const char *path, uint8_t **out_bytes, size_t *out_len, char *err, size_t err_len) {
  FILE *fp;
  long size;
  uint8_t *bytes;
  size_t nread;

  if (path == NULL || out_bytes == NULL || out_len == NULL) {
    write_err(err, err_len, "read_file invalid args");
    return -1;
  }

  fp = fopen(path, "rb");
  if (fp == NULL) {
    write_err(err, err_len, "failed to open '%s'", path);
    return -1;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    write_err(err, err_len, "failed to seek '%s'", path);
    return -1;
  }

  size = ftell(fp);
  if (size < 0) {
    fclose(fp);
    write_err(err, err_len, "failed to get size '%s'", path);
    return -1;
  }

  if (fseek(fp, 0, SEEK_SET) != 0) {
    fclose(fp);
    write_err(err, err_len, "failed to rewind '%s'", path);
    return -1;
  }

  bytes = (uint8_t *)malloc((size_t)size);
  if (bytes == NULL) {
    fclose(fp);
    write_err(err, err_len, "allocation failed for '%s'", path);
    return -1;
  }

  nread = fread(bytes, 1, (size_t)size, fp);
  fclose(fp);

  if (nread != (size_t)size) {
    free(bytes);
    write_err(err, err_len, "short read for '%s'", path);
    return -1;
  }

  *out_bytes = bytes;
  *out_len = (size_t)size;
  return 0;
}

static int resolve_host_user_id(const steel_policy_t *policy,
                                char *buf,
                                size_t buf_len,
                                const char **out_user_id,
                                char *err,
                                size_t err_len) {
  const char *env_user;
  if (out_user_id == NULL) {
    write_err(err, err_len, "permission negotiation invalid args");
    return -1;
  }
  if (policy != NULL && policy->host_user_id != NULL && policy->host_user_id[0] != '\0') {
    *out_user_id = policy->host_user_id;
    return 0;
  }

  env_user = getenv("USER");
  if (env_user != NULL && env_user[0] != '\0') {
    *out_user_id = env_user;
    return 0;
  }

#if defined(__unix__) || defined(__APPLE__)
  if (buf != NULL && buf_len > 0) {
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL && pw->pw_name[0] != '\0') {
      size_t n = strlen(pw->pw_name);
      if (n >= buf_len) {
        write_err(err, err_len, "host user id buffer too small");
        return -1;
      }
      memcpy(buf, pw->pw_name, n + 1);
      *out_user_id = buf;
      return 0;
    }
  }
#endif

  write_err(err, err_len, "unable to resolve host user id");
  return -1;
}

static int signer_matches_rule(const steel_manifest_t *manifest, const char *rule_signer_id) {
  size_t n;
  if (rule_signer_id == NULL || rule_signer_id[0] == '\0' || strcmp(rule_signer_id, "*") == 0) {
    return 1;
  }
  if (manifest == NULL || manifest->signer_id == NULL) {
    return 0;
  }
  n = strlen(rule_signer_id);
  return n == manifest->signer_id_len && memcmp(rule_signer_id, manifest->signer_id, n) == 0;
}

static int host_user_matches_rule(const char *host_user_id, const char *rule_host_user_id) {
  if (rule_host_user_id == NULL || rule_host_user_id[0] == '\0' || strcmp(rule_host_user_id, "*") == 0) {
    return 1;
  }
  if (host_user_id == NULL) {
    return 0;
  }
  return strcmp(host_user_id, rule_host_user_id) == 0;
}

static uint32_t rule_allowed_for_facet(const steel_permission_rule_t *rule,
                                       const uint8_t facet_id_bytes[16],
                                       uint32_t default_allowed) {
  size_t i;
  if (rule == NULL || facet_id_bytes == NULL) {
    return default_allowed;
  }
  if (rule->facet_permissions == NULL || rule->facet_permission_count == 0) {
    return default_allowed;
  }
  for (i = 0; i < rule->facet_permission_count; ++i) {
    const steel_facet_permission_rule_t *facet_rule = &rule->facet_permissions[i];
    if (memcmp(facet_rule->facet_id.bytes, facet_id_bytes, 16) == 0) {
      return facet_rule->allowed_permissions & STEEL_PLUGIN_KNOWN_PERMISSIONS;
    }
  }
  return default_allowed;
}

static int negotiate_allowed_permissions(const steel_manifest_t *manifest,
                                         const steel_policy_t *policy,
                                         uint32_t *out_allowed_permissions,
                                         uint32_t *out_allowed_permissions_per_facet,
                                         char *err,
                                         size_t err_len) {
  char host_user_buf[128];
  const char *host_user_id = NULL;
  size_t i;
  if (manifest == NULL || policy == NULL || out_allowed_permissions == NULL) {
    write_err(err, err_len, "permission negotiation missing args");
    return -1;
  }

  if (resolve_host_user_id(policy, host_user_buf, sizeof(host_user_buf), &host_user_id, err, err_len) != 0) {
    return -1;
  }

  if (policy->permission_rules != NULL && policy->permission_rule_count > 0) {
    for (i = 0; i < policy->permission_rule_count; ++i) {
      const steel_permission_rule_t *rule = &policy->permission_rules[i];
      size_t j;
      if (!signer_matches_rule(manifest, rule->signer_id)) {
        continue;
      }
      if (!host_user_matches_rule(host_user_id, rule->host_user_id)) {
        continue;
      }
      *out_allowed_permissions = rule->allowed_permissions & STEEL_PLUGIN_KNOWN_PERMISSIONS;
      if (out_allowed_permissions_per_facet != NULL) {
        for (j = 0; j < manifest->facet_count; ++j) {
          out_allowed_permissions_per_facet[j] =
              rule_allowed_for_facet(rule, manifest->facets[j].id_bytes, *out_allowed_permissions);
        }
      }
      return 0;
    }
    *out_allowed_permissions = 0;
    if (out_allowed_permissions_per_facet != NULL) {
      memset(out_allowed_permissions_per_facet, 0, manifest->facet_count * sizeof(*out_allowed_permissions_per_facet));
    }
    return 0;
  }

  *out_allowed_permissions = policy->allowed_plugin_permissions & STEEL_PLUGIN_KNOWN_PERMISSIONS;
  if (out_allowed_permissions_per_facet != NULL) {
    for (i = 0; i < manifest->facet_count; ++i) {
      out_allowed_permissions_per_facet[i] = *out_allowed_permissions;
    }
  }
  return 0;
}

static void write_u32_wire(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value & 0xffu);
  dst[1] = (uint8_t)((value >> 8) & 0xffu);
  dst[2] = (uint8_t)((value >> 16) & 0xffu);
  dst[3] = (uint8_t)((value >> 24) & 0xffu);
}

static void write_u16_wire(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value & 0xffu);
  dst[1] = (uint8_t)((value >> 8) & 0xffu);
}

static void write_u64_wire(uint8_t *dst, uint64_t value) {
  dst[0] = (uint8_t)(value & 0xffu);
  dst[1] = (uint8_t)((value >> 8) & 0xffu);
  dst[2] = (uint8_t)((value >> 16) & 0xffu);
  dst[3] = (uint8_t)((value >> 24) & 0xffu);
  dst[4] = (uint8_t)((value >> 32) & 0xffu);
  dst[5] = (uint8_t)((value >> 40) & 0xffu);
  dst[6] = (uint8_t)((value >> 48) & 0xffu);
  dst[7] = (uint8_t)((value >> 56) & 0xffu);
}

static uint16_t read_u16_wire(const uint8_t *src) { return (uint16_t)(((uint16_t)src[0]) | ((uint16_t)src[1] << 8)); }

static uint32_t read_u32_wire(const uint8_t *src) {
  return ((uint32_t)src[0]) | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16) | ((uint32_t)src[3] << 24);
}

static uint64_t read_u64_wire(const uint8_t *src) {
  return ((uint64_t)src[0]) | ((uint64_t)src[1] << 8) | ((uint64_t)src[2] << 16) | ((uint64_t)src[3] << 24) |
         ((uint64_t)src[4] << 32) | ((uint64_t)src[5] << 40) | ((uint64_t)src[6] << 48) | ((uint64_t)src[7] << 56);
}

static int marshal_value_size(const steel_typed_value_t *arg, size_t *out_size, char *err, size_t err_len) {
  if (arg == NULL || out_size == NULL) {
    write_err(err, err_len, "typed invoke invalid value");
    return -1;
  }

  switch (arg->type) {
    case STEEL_SIG_TYPE_VOID:
      *out_size = 0;
      return 0;
    case STEEL_SIG_TYPE_BOOL:
      *out_size = 1;
      return 0;
    case STEEL_SIG_TYPE_CHAR:
    case STEEL_SIG_TYPE_SCHAR:
    case STEEL_SIG_TYPE_UCHAR:
      *out_size = 1;
      return 0;
    case STEEL_SIG_TYPE_SHORT:
    case STEEL_SIG_TYPE_USHORT:
      *out_size = 2;
      return 0;
    case STEEL_SIG_TYPE_INT:
    case STEEL_SIG_TYPE_UINT:
    case STEEL_SIG_TYPE_U32:
    case STEEL_SIG_TYPE_FLOAT:
      *out_size = 4;
      return 0;
    case STEEL_SIG_TYPE_LONG:
    case STEEL_SIG_TYPE_ULONG:
    case STEEL_SIG_TYPE_LLONG:
    case STEEL_SIG_TYPE_ULLONG:
    case STEEL_SIG_TYPE_DOUBLE:
    case STEEL_SIG_TYPE_VOID_PTR:
    case STEEL_SIG_TYPE_OBJ_PTR:
      *out_size = 8;
      return 0;
    case STEEL_SIG_TYPE_LDOUBLE:
      *out_size = sizeof(long double);
      return 0;
    case STEEL_SIG_TYPE_BYTES:
      if (arg->as.bytes.len > UINT32_MAX) {
        write_err(err, err_len, "typed invoke bytes arg too large");
        return -1;
      }
      *out_size = 4 + arg->as.bytes.len;
      return 0;
    default:
      write_err(err, err_len, "typed invoke unsupported argument type=%u", (unsigned)arg->type);
      return -1;
  }
}

static int marshal_value(const steel_typed_value_t *arg, uint8_t *dst, size_t dst_len, char *err, size_t err_len) {
  if (arg == NULL || dst == NULL) {
    write_err(err, err_len, "typed invoke marshal invalid args");
    return -1;
  }

  switch (arg->type) {
    case STEEL_SIG_TYPE_VOID:
      return 0;
    case STEEL_SIG_TYPE_U32:
      if (dst_len < 4) {
        write_err(err, err_len, "typed invoke marshal underflow (u32)");
        return -1;
      }
      write_u32_wire(dst, arg->as.u32);
      return 0;
    case STEEL_SIG_TYPE_BOOL:
      if (dst_len < 1) {
        write_err(err, err_len, "typed invoke marshal underflow (bool)");
        return -1;
      }
      dst[0] = arg->as.boolean ? 1 : 0;
      return 0;
    case STEEL_SIG_TYPE_CHAR:
      if (dst_len < 1) {
        write_err(err, err_len, "typed invoke marshal underflow (char)");
        return -1;
      }
      dst[0] = (uint8_t)arg->as.c;
      return 0;
    case STEEL_SIG_TYPE_SCHAR:
      if (dst_len < 1) {
        write_err(err, err_len, "typed invoke marshal underflow (schar)");
        return -1;
      }
      dst[0] = (uint8_t)arg->as.sc;
      return 0;
    case STEEL_SIG_TYPE_UCHAR:
      if (dst_len < 1) {
        write_err(err, err_len, "typed invoke marshal underflow (uchar)");
        return -1;
      }
      dst[0] = arg->as.uc;
      return 0;
    case STEEL_SIG_TYPE_SHORT:
      if (dst_len < 2) {
        write_err(err, err_len, "typed invoke marshal underflow (short)");
        return -1;
      }
      write_u16_wire(dst, (uint16_t)arg->as.s);
      return 0;
    case STEEL_SIG_TYPE_USHORT:
      if (dst_len < 2) {
        write_err(err, err_len, "typed invoke marshal underflow (ushort)");
        return -1;
      }
      write_u16_wire(dst, arg->as.us);
      return 0;
    case STEEL_SIG_TYPE_INT:
      if (dst_len < 4) {
        write_err(err, err_len, "typed invoke marshal underflow (int)");
        return -1;
      }
      write_u32_wire(dst, (uint32_t)arg->as.i);
      return 0;
    case STEEL_SIG_TYPE_UINT:
      if (dst_len < 4) {
        write_err(err, err_len, "typed invoke marshal underflow (uint)");
        return -1;
      }
      write_u32_wire(dst, arg->as.ui);
      return 0;
    case STEEL_SIG_TYPE_FLOAT: {
      uint32_t bits = 0;
      if (dst_len < 4) {
        write_err(err, err_len, "typed invoke marshal underflow (float)");
        return -1;
      }
      memcpy(&bits, &arg->as.f, sizeof(bits));
      write_u32_wire(dst, bits);
      return 0;
    }
    case STEEL_SIG_TYPE_LONG:
      if (dst_len < 8) {
        write_err(err, err_len, "typed invoke marshal underflow (long)");
        return -1;
      }
      write_u64_wire(dst, (uint64_t)arg->as.l);
      return 0;
    case STEEL_SIG_TYPE_ULONG:
      if (dst_len < 8) {
        write_err(err, err_len, "typed invoke marshal underflow (ulong)");
        return -1;
      }
      write_u64_wire(dst, (uint64_t)arg->as.ul);
      return 0;
    case STEEL_SIG_TYPE_LLONG:
      if (dst_len < 8) {
        write_err(err, err_len, "typed invoke marshal underflow (llong)");
        return -1;
      }
      write_u64_wire(dst, (uint64_t)arg->as.ll);
      return 0;
    case STEEL_SIG_TYPE_ULLONG:
      if (dst_len < 8) {
        write_err(err, err_len, "typed invoke marshal underflow (ullong)");
        return -1;
      }
      write_u64_wire(dst, (uint64_t)arg->as.ull);
      return 0;
    case STEEL_SIG_TYPE_DOUBLE: {
      uint64_t bits = 0;
      if (dst_len < 8) {
        write_err(err, err_len, "typed invoke marshal underflow (double)");
        return -1;
      }
      memcpy(&bits, &arg->as.d, sizeof(bits));
      write_u64_wire(dst, bits);
      return 0;
    }
    case STEEL_SIG_TYPE_LDOUBLE:
      if (dst_len < sizeof(long double)) {
        write_err(err, err_len, "typed invoke marshal underflow (ldouble)");
        return -1;
      }
      memcpy(dst, &arg->as.ld, sizeof(long double));
      return 0;
    case STEEL_SIG_TYPE_VOID_PTR:
    case STEEL_SIG_TYPE_OBJ_PTR:
      if (dst_len < 8) {
        write_err(err, err_len, "typed invoke marshal underflow (ptr)");
        return -1;
      }
      write_u64_wire(dst, (uint64_t)arg->as.ptr);
      return 0;
    case STEEL_SIG_TYPE_BYTES:
      if (dst_len < 4 + arg->as.bytes.len) {
        write_err(err, err_len, "typed invoke marshal underflow (bytes)");
        return -1;
      }
      write_u32_wire(dst, (uint32_t)arg->as.bytes.len);
      if (arg->as.bytes.len > 0) {
        if (arg->as.bytes.ptr == NULL) {
          write_err(err, err_len, "typed invoke bytes arg NULL with non-zero len");
          return -1;
        }
        memcpy(dst + 4, arg->as.bytes.ptr, arg->as.bytes.len);
      }
      return 0;
    default:
      write_err(err, err_len, "typed invoke unsupported argument type=%u", (unsigned)arg->type);
      return -1;
  }
}

int steel_plugin_load(steel_plugin_t *plugin,
                      const char *path,
                      const steel_policy_t *policy,
                      const steel_engine_vtable_t *engine,
                      char *err,
                      size_t err_len) {
  uint8_t *bytes = NULL;
  size_t len = 0;
  uint32_t default_region_bytes;
  uint32_t plugin_region_bytes;
  uint32_t allowed_permissions = 0;
  uint32_t *allowed_permissions_per_facet = NULL;
  size_t i;

  if (plugin == NULL || path == NULL || policy == NULL || engine == NULL) {
    write_err(err, err_len, "plugin_load missing args");
    return -1;
  }

  memset(plugin, 0, sizeof(*plugin));
  plugin->engine = *engine;
  (void)steel_builtin_contracts_linked();

  if (read_file(path, &bytes, &len, err, err_len) != 0) {
    return -1;
  }

  if (steel_extract_manifest_from_component(bytes, len, &plugin->manifest, err, err_len) != 0) {
    steel_manifest_free(&plugin->manifest);
    steel_region_destroy(&plugin->plugin_region);
    free(bytes);
    return -1;
  }
  plugin->manifest.owned_component_bytes = bytes;
  plugin->manifest.owned_component_len = len;

  if (steel_verify_manifest(&plugin->manifest, policy, err, err_len) != 0) {
    steel_manifest_free(&plugin->manifest);
    return -1;
  }

  default_region_bytes = policy->default_plugin_region_bytes > 0 ? policy->default_plugin_region_bytes
                                                                  : STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  plugin_region_bytes =
      plugin->manifest.requested_region_bytes > 0 ? plugin->manifest.requested_region_bytes : default_region_bytes;
  plugin->plugin_region_allotment_bytes = plugin_region_bytes;
  steel_region_init_with_limit(&plugin->plugin_region, plugin_region_bytes, plugin_region_bytes);

  if (plugin->manifest.facet_count > 0) {
    allowed_permissions_per_facet = (uint32_t *)calloc(plugin->manifest.facet_count, sizeof(uint32_t));
    if (allowed_permissions_per_facet == NULL) {
      write_err(err, err_len, "facet permission allocation failed");
      steel_manifest_free(&plugin->manifest);
      steel_region_destroy(&plugin->plugin_region);
      return -1;
    }
  }

  if (negotiate_allowed_permissions(
          &plugin->manifest, policy, &allowed_permissions, allowed_permissions_per_facet, err, err_len) != 0) {
    free(allowed_permissions_per_facet);
    steel_manifest_free(&plugin->manifest);
    steel_region_destroy(&plugin->plugin_region);
    return -1;
  }

  plugin->facet_granted_permissions = NULL;
  if (plugin->manifest.facet_count > 0) {
    plugin->facet_granted_permissions = (uint32_t *)calloc(plugin->manifest.facet_count, sizeof(uint32_t));
    if (plugin->facet_granted_permissions == NULL) {
      free(allowed_permissions_per_facet);
      write_err(err, err_len, "facet granted permission allocation failed");
      steel_manifest_free(&plugin->manifest);
      steel_region_destroy(&plugin->plugin_region);
      return -1;
    }
    for (i = 0; i < plugin->manifest.facet_count; ++i) {
      plugin->facet_granted_permissions[i] =
          plugin->manifest.facets[i].requested_permissions & allowed_permissions_per_facet[i];
    }
  }
  free(allowed_permissions_per_facet);
  plugin->granted_permissions = plugin->manifest.requested_permissions & allowed_permissions;

  if (plugin->engine.open_component(plugin, path, err, err_len) != 0) {
    free(plugin->facet_granted_permissions);
    plugin->facet_granted_permissions = NULL;
    steel_manifest_free(&plugin->manifest);
    steel_region_destroy(&plugin->plugin_region);
    return -1;
  }

  return 0;
}

int steel_plugin_invoke(steel_plugin_t *plugin,
                        const steel_call_t *call,
                        steel_result_t *result,
                        char *err,
                        size_t err_len) {
  const steel_vtable_entry_t *contract;
  steel_call_t engine_call;
  uint8_t *plugin_input = NULL;
  uint32_t host_region_bytes;
  uint32_t granted_permissions_for_facet;
  size_t i;

  if (plugin == NULL || call == NULL || result == NULL) {
    write_err(err, err_len, "plugin_invoke missing args");
    return -1;
  }

  host_region_bytes = plugin->plugin_region_allotment_bytes > 0 ? plugin->plugin_region_allotment_bytes
                                                                 : STEEL_DEFAULT_PLUGIN_REGION_BYTES;

  if (result->storage_magic != STEEL_RESULT_STORAGE_MAGIC || !result->storage_initialized) {
    memset(&result->storage, 0, sizeof(result->storage));
    steel_region_init_with_limit(&result->storage, host_region_bytes, host_region_bytes);
    result->storage_magic = STEEL_RESULT_STORAGE_MAGIC;
    result->storage_initialized = 1;
  }
  steel_region_reset(&result->storage);
  result->output = NULL;
  result->output_len = 0;

  steel_region_reset(&plugin->plugin_region);

  if (call->input_len > 0 && call->input == NULL) {
    write_err(err, err_len, "input pointer is NULL with non-zero input_len");
    return -1;
  }

  contract = steel_contract_find(&call->facet_id, call->method_id);
  if (contract == NULL) {
    write_err(err, err_len, "unknown facet/method call");
    return -1;
  }

  if ((call->permissions & STEEL_CALL_PERM_INPUT_IS_CRITICAL) != 0 &&
      (call->permissions & STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK) != 0) {
    write_err(err, err_len, "critical host memory cannot be copy-back write-enabled for plugin calls");
    return -1;
  }

  engine_call = *call;
  if (call->input_len > 0) {
    plugin_input = (uint8_t *)steel_region_alloc(&plugin->plugin_region, call->input_len, 1);
    if (plugin_input == NULL) {
      write_err(err,
                err_len,
                "plugin input allocation failed (requested=%zu, allotment=%u)",
                call->input_len,
                plugin->plugin_region_allotment_bytes);
      return -1;
    }
    memcpy(plugin_input, call->input, call->input_len);
    engine_call.input = plugin_input;
  } else {
    engine_call.input = NULL;
  }

  if (plugin->engine.invoke(plugin, &engine_call, result, err, err_len) != 0) {
    return -1;
  }

  granted_permissions_for_facet = plugin->granted_permissions;
  if (plugin->facet_granted_permissions != NULL) {
    for (i = 0; i < plugin->manifest.facet_count; ++i) {
      if (memcmp(plugin->manifest.facets[i].id_bytes, call->facet_id.bytes, 16) == 0) {
        granted_permissions_for_facet = plugin->facet_granted_permissions[i];
        break;
      }
    }
  }

  if ((call->permissions & granted_permissions_for_facet & STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK) != 0 &&
      call->input_len > 0) {
    memcpy(call->input, plugin_input, call->input_len);
  }

  if (result->output_len > 0) {
    uint8_t *host_copy = (uint8_t *)steel_region_alloc(&result->storage, result->output_len, 1);
    if (host_copy == NULL) {
      write_err(err, err_len, "host result allocation failed");
      return -1;
    }
    memcpy(host_copy, result->output, result->output_len);
    result->output = host_copy;
  } else {
    result->output = NULL;
  }

  return 0;
}

int steel_plugin_invoke_typed(steel_plugin_t *plugin,
                              const steel_facet_id_t *facet_id,
                              uint32_t method_id,
                              uint32_t receiver_handle,
                              uint32_t permissions,
                              const steel_typed_value_t *args,
                              size_t arg_count,
                              steel_typed_result_t *result,
                              char *err,
                              size_t err_len) {
  const steel_vtable_entry_t *contract;
  steel_call_t call;
  uint8_t *payload = NULL;
  size_t payload_len = 0;
  size_t offset = 0;
  size_t i;

  if (plugin == NULL || facet_id == NULL || result == NULL) {
    write_err(err, err_len, "typed invoke missing args");
    return -1;
  }

  memset(result, 0, sizeof(*result));
  contract = steel_contract_find(facet_id, method_id);
  if (contract == NULL) {
    write_err(err, err_len, "typed invoke unknown facet/method");
    return -1;
  }
  if (arg_count != contract->steel_fun_signature.param_count) {
    write_err(err,
              err_len,
              "typed invoke arg count mismatch: expected=%zu got=%zu",
              contract->steel_fun_signature.param_count,
              arg_count);
    return -1;
  }

  for (i = 0; i < arg_count; ++i) {
    size_t sz = 0;
    if (args == NULL) {
      write_err(err, err_len, "typed invoke args NULL with non-zero arg_count");
      return -1;
    }
    if (args[i].type != contract->steel_fun_signature.param_types[i]) {
      write_err(err,
                err_len,
                "typed invoke arg[%zu] type mismatch: expected=%u got=%u",
                i,
                (unsigned)contract->steel_fun_signature.param_types[i],
                (unsigned)args[i].type);
      return -1;
    }
    if (marshal_value_size(&args[i], &sz, err, err_len) != 0) {
      return -1;
    }
    if (payload_len > (size_t)-1 - sz) {
      write_err(err, err_len, "typed invoke payload size overflow");
      return -1;
    }
    payload_len += sz;
  }

  if (payload_len > 0) {
    payload = (uint8_t *)malloc(payload_len);
    if (payload == NULL) {
      write_err(err, err_len, "typed invoke payload allocation failed");
      return -1;
    }
    for (i = 0; i < arg_count; ++i) {
      size_t sz = 0;
      if (marshal_value_size(&args[i], &sz, err, err_len) != 0) {
        free(payload);
        return -1;
      }
      if (marshal_value(&args[i], payload + offset, sz, err, err_len) != 0) {
        free(payload);
        return -1;
      }
      offset += sz;
    }
  }

  memset(&call, 0, sizeof(call));
  call.facet_id = *facet_id;
  call.method_id = method_id;
  call.receiver_handle = receiver_handle;
  call.permissions = permissions;
  call.input = payload;
  call.input_len = payload_len;

  if (steel_plugin_invoke(plugin, &call, &result->raw, err, err_len) != 0) {
    free(payload);
    return -1;
  }
  free(payload);

  result->value.type = contract->steel_fun_signature.result_type;
  switch (result->value.type) {
    case STEEL_SIG_TYPE_VOID:
      if (result->raw.output_len != 0) {
        write_err(err, err_len, "typed invoke expected void result but got %zu bytes", result->raw.output_len);
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      return 0;
    case STEEL_SIG_TYPE_BOOL:
      if (result->raw.output_len != 1 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected bool result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.boolean = result->raw.output[0] ? 1 : 0;
      return 0;
    case STEEL_SIG_TYPE_CHAR:
      if (result->raw.output_len != 1 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected char result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.c = (char)result->raw.output[0];
      return 0;
    case STEEL_SIG_TYPE_SCHAR:
      if (result->raw.output_len != 1 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected schar result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.sc = (signed char)result->raw.output[0];
      return 0;
    case STEEL_SIG_TYPE_UCHAR:
      if (result->raw.output_len != 1 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected uchar result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.uc = result->raw.output[0];
      return 0;
    case STEEL_SIG_TYPE_SHORT:
      if (result->raw.output_len != 2 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected short result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.s = (short)read_u16_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_USHORT:
      if (result->raw.output_len != 2 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected ushort result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.us = read_u16_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_INT:
      if (result->raw.output_len != 4 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected int result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.i = (int)read_u32_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_UINT:
      if (result->raw.output_len != 4 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected uint result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.ui = read_u32_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_U32:
      if (result->raw.output_len != 4 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected u32 result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.u32 = read_u32_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_FLOAT: {
      uint32_t bits = 0;
      if (result->raw.output_len != 4 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected float result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      bits = read_u32_wire(result->raw.output);
      memcpy(&result->value.as.f, &bits, sizeof(bits));
      return 0;
    }
    case STEEL_SIG_TYPE_LONG:
      if (result->raw.output_len != 8 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected long result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.l = (long)read_u64_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_ULONG:
      if (result->raw.output_len != 8 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected ulong result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.ul = (unsigned long)read_u64_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_LLONG:
      if (result->raw.output_len != 8 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected llong result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.ll = (long long)read_u64_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_ULLONG:
      if (result->raw.output_len != 8 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected ullong result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.ull = (unsigned long long)read_u64_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_DOUBLE: {
      uint64_t bits = 0;
      if (result->raw.output_len != 8 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected double result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      bits = read_u64_wire(result->raw.output);
      memcpy(&result->value.as.d, &bits, sizeof(bits));
      return 0;
    }
    case STEEL_SIG_TYPE_LDOUBLE:
      if (result->raw.output_len != sizeof(long double) || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected ldouble result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      memcpy(&result->value.as.ld, result->raw.output, sizeof(long double));
      return 0;
    case STEEL_SIG_TYPE_VOID_PTR:
    case STEEL_SIG_TYPE_OBJ_PTR:
      if (result->raw.output_len != 8 || result->raw.output == NULL) {
        write_err(err, err_len, "typed invoke expected pointer result encoding");
        steel_result_free(&result->raw);
        memset(result, 0, sizeof(*result));
        return -1;
      }
      result->value.as.ptr = (uintptr_t)read_u64_wire(result->raw.output);
      return 0;
    case STEEL_SIG_TYPE_BYTES:
      result->value.as.bytes.ptr = result->raw.output;
      result->value.as.bytes.len = result->raw.output_len;
      return 0;
    default:
      write_err(err, err_len, "typed invoke unsupported result type=%u", (unsigned)result->value.type);
      steel_result_free(&result->raw);
      memset(result, 0, sizeof(*result));
      return -1;
  }
}

void steel_result_free(steel_result_t *result) {
  if (result == NULL) {
    return;
  }
  if (result->storage_initialized) {
    steel_region_destroy(&result->storage);
    result->storage_initialized = 0;
  }
  result->storage_magic = 0;
  result->output = NULL;
  result->output_len = 0;
}

void steel_typed_result_free(steel_typed_result_t *result) {
  if (result == NULL) {
    return;
  }
  steel_result_free(&result->raw);
  memset(result, 0, sizeof(*result));
}

void steel_plugin_unload(steel_plugin_t *plugin) {
  if (plugin == NULL) {
    return;
  }
  if (plugin->engine.close != NULL) {
    plugin->engine.close(plugin);
  }
  free(plugin->facet_granted_permissions);
  plugin->facet_granted_permissions = NULL;
  steel_region_destroy(&plugin->plugin_region);
  steel_manifest_free(&plugin->manifest);
  memset(plugin, 0, sizeof(*plugin));
}
