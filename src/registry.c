#include "steel/registry.h"

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

static char *dup_cstr(const char *s) {
  size_t n;
  char *out;
  if (s == NULL) {
    return NULL;
  }
  n = strlen(s);
  out = (char *)malloc(n + 1);
  if (out == NULL) {
    return NULL;
  }
  memcpy(out, s, n + 1);
  return out;
}

static char *dup_len(const char *s, size_t n) {
  char *out;
  if (s == NULL) {
    return NULL;
  }
  out = (char *)malloc(n + 1);
  if (out == NULL) {
    return NULL;
  }
  if (n > 0) {
    memcpy(out, s, n);
  }
  out[n] = '\0';
  return out;
}

void steel_registry_init(steel_registry_t *registry) {
  if (registry == NULL) {
    return;
  }
  memset(registry, 0, sizeof(*registry));
}

void steel_registry_free(steel_registry_t *registry) {
  size_t i;
  if (registry == NULL) {
    return;
  }
  for (i = 0; i < registry->object_count; ++i) {
    free((void *)registry->objects[i].type_name);
  }
  for (i = 0; i < registry->object_type_count; ++i) {
    free((void *)registry->object_types[i].facets);
    free((void *)registry->object_types[i].name);
  }
  free(registry->facets);
  free(registry->methods);
  free(registry->object_types);
  free(registry->objects);
  memset(registry, 0, sizeof(*registry));
}

int steel_registry_build(steel_plugin_t *plugin, steel_registry_t *registry, char *err, size_t err_len) {
  size_t i;
  size_t method_cursor = 0;

  if (plugin == NULL || registry == NULL) {
    write_err(err, err_len, "registry_build missing args");
    return -1;
  }

  steel_registry_free(registry);
  registry->plugin = plugin;
  registry->facet_count = plugin->manifest.facet_count;
  registry->method_count = plugin->manifest.method_count;
  registry->object_type_count = plugin->manifest.object_type_count;

  if (registry->facet_count > 0) {
    registry->facets = (steel_registry_facet_t *)calloc(registry->facet_count, sizeof(*registry->facets));
    if (registry->facets == NULL) {
      write_err(err, err_len, "registry facet allocation failed");
      return -1;
    }
  }
  if (registry->method_count > 0) {
    registry->methods = (steel_registry_method_t *)calloc(registry->method_count, sizeof(*registry->methods));
    if (registry->methods == NULL) {
      write_err(err, err_len, "registry method allocation failed");
      return -1;
    }
  }
  if (registry->object_type_count > 0) {
    registry->object_types =
        (steel_registry_object_type_t *)calloc(registry->object_type_count, sizeof(*registry->object_types));
    if (registry->object_types == NULL) {
      write_err(err, err_len, "registry object type allocation failed");
      steel_registry_free(registry);
      return -1;
    }
    for (i = 0; i < registry->object_type_count; ++i) {
      const steel_manifest_object_type_t *src = &plugin->manifest.object_types[i];
      char *name = dup_len(src->name, src->name_len);
      steel_facet_id_t *facets = NULL;
      size_t j;
      if (name == NULL) {
        write_err(err, err_len, "registry object type name allocation failed");
        steel_registry_free(registry);
        return -1;
      }
      if (src->facet_count > 0) {
        facets = (steel_facet_id_t *)calloc(src->facet_count, sizeof(*facets));
        if (facets == NULL) {
          free(name);
          write_err(err, err_len, "registry object type facet allocation failed");
          steel_registry_free(registry);
          return -1;
        }
        for (j = 0; j < src->facet_count; ++j) {
          uint32_t facet_index = src->facet_indices[j];
          memcpy(facets[j].bytes, plugin->manifest.facets[facet_index].id_bytes, sizeof(facets[j].bytes));
        }
      }
      registry->object_types[i].name = name;
      registry->object_types[i].facets = facets;
      registry->object_types[i].facet_count = src->facet_count;
    }
  }

  for (i = 0; i < registry->facet_count; ++i) {
    const steel_manifest_facet_t *mf = &plugin->manifest.facets[i];
    steel_registry_facet_t *rf = &registry->facets[i];
    size_t j;

    if (method_cursor + mf->method_count > registry->method_count) {
      write_err(err, err_len, "registry method cursor overflow");
      steel_registry_free(registry);
      return -1;
    }

    memcpy(rf->facet_id.bytes, mf->id_bytes, 16);
    rf->methods = &registry->methods[method_cursor];
    rf->method_count = mf->method_count;

    for (j = 0; j < mf->method_count; ++j) {
      const steel_manifest_method_t *mm = &plugin->manifest.methods[mf->method_start + j];
      steel_registry_method_t *rm = &registry->methods[method_cursor + j];
      const steel_vtable_entry_t *contract = steel_contract_find_by_facet_bytes(mf->id_bytes, mm->method_id);

      rm->method_id = mm->method_id;
      rm->method_name = (contract != NULL && contract->method_name != NULL) ? contract->method_name : "<unknown>";
      rm->signature = (contract != NULL) ? contract->steel_fun_signature : mm->steel_fun_signature;
    }

    method_cursor += mf->method_count;
  }

  return 0;
}

size_t steel_registry_facet_count(const steel_registry_t *registry) {
  return registry != NULL ? registry->facet_count : 0;
}

const steel_registry_facet_t *steel_registry_facet_get(const steel_registry_t *registry, size_t idx) {
  if (registry == NULL || idx >= registry->facet_count) {
    return NULL;
  }
  return &registry->facets[idx];
}

size_t steel_registry_object_count(const steel_registry_t *registry) {
  return registry != NULL ? registry->object_count : 0;
}

size_t steel_registry_object_type_count(const steel_registry_t *registry) {
  return registry != NULL ? registry->object_type_count : 0;
}

const steel_registry_object_type_t *steel_registry_object_type_get(const steel_registry_t *registry, size_t idx) {
  if (registry == NULL || idx >= registry->object_type_count) {
    return NULL;
  }
  return &registry->object_types[idx];
}

const steel_object_t *steel_registry_object_get(const steel_registry_t *registry, size_t idx) {
  if (registry == NULL || idx >= registry->object_count) {
    return NULL;
  }
  return &registry->objects[idx];
}

static const steel_registry_object_type_t *registry_find_object_type_by_name(const steel_registry_t *registry,
                                                                              const char *object_type_name) {
  size_t i;
  if (registry == NULL || object_type_name == NULL) {
    return NULL;
  }
  for (i = 0; i < registry->object_type_count; ++i) {
    const char *name = registry->object_types[i].name;
    if (name != NULL && strcmp(name, object_type_name) == 0) {
      return &registry->object_types[i];
    }
  }
  return NULL;
}

static int object_type_matches_aggregate(const steel_registry_object_type_t *object_type,
                                         const steel_aggregate_type_t *aggregate) {
  size_t i;
  if (object_type == NULL || aggregate == NULL) {
    return 0;
  }
  if (aggregate->required_facet_count == 0) {
    return 1;
  }
  if (aggregate->required_facets == NULL) {
    return 0;
  }
  for (i = 0; i < aggregate->required_facet_count; ++i) {
    size_t j;
    int found = 0;
    for (j = 0; j < object_type->facet_count; ++j) {
      if (steel_facet_id_equal(&aggregate->required_facets[i], &object_type->facets[j])) {
        found = 1;
        break;
      }
    }
    if (!found) {
      return 0;
    }
  }
  return 1;
}

static int compare_object_types_for_aggregate(const steel_registry_object_type_t *a,
                                              size_t a_idx,
                                              const steel_registry_object_type_t *b,
                                              size_t b_idx) {
  int name_cmp;
  const char *a_name = (a != NULL && a->name != NULL) ? a->name : "";
  const char *b_name = (b != NULL && b->name != NULL) ? b->name : "";

  if (a != NULL && b != NULL && a->facet_count != b->facet_count) {
    return a->facet_count < b->facet_count ? -1 : 1;
  }

  name_cmp = strcmp(a_name, b_name);
  if (name_cmp != 0) {
    return name_cmp < 0 ? -1 : 1;
  }

  if (a_idx != b_idx) {
    return a_idx < b_idx ? -1 : 1;
  }
  return 0;
}

size_t steel_registry_find_object_types_by_aggregate(const steel_registry_t *registry,
                                                     const steel_aggregate_type_t *aggregate,
                                                     const steel_registry_object_type_t **out_matches,
                                                     size_t out_capacity) {
  const steel_registry_object_type_t **matches = NULL;
  size_t *match_indices = NULL;
  size_t i;
  size_t match_count = 0;
  size_t total = 0;
  if (registry == NULL || aggregate == NULL) {
    return 0;
  }
  if (registry->object_type_count > 0) {
    matches = (const steel_registry_object_type_t **)calloc(registry->object_type_count, sizeof(*matches));
    match_indices = (size_t *)calloc(registry->object_type_count, sizeof(*match_indices));
  }
  for (i = 0; i < registry->object_type_count; ++i) {
    const steel_registry_object_type_t *object_type = &registry->object_types[i];
    if (!object_type_matches_aggregate(object_type, aggregate)) {
      continue;
    }
    total += 1;
    if (matches != NULL && match_indices != NULL) {
      matches[match_count] = object_type;
      match_indices[match_count] = i;
      match_count += 1;
    }
  }

  if (matches != NULL && match_indices != NULL && match_count > 1) {
    size_t a;
    for (a = 0; a + 1 < match_count; ++a) {
      size_t b;
      size_t best = a;
      for (b = a + 1; b < match_count; ++b) {
        if (compare_object_types_for_aggregate(
                matches[b], match_indices[b], matches[best], match_indices[best]) < 0) {
          best = b;
        }
      }
      if (best != a) {
        const steel_registry_object_type_t *tmp_match = matches[a];
        size_t tmp_index = match_indices[a];
        matches[a] = matches[best];
        match_indices[a] = match_indices[best];
        matches[best] = tmp_match;
        match_indices[best] = tmp_index;
      }
    }
  }

  if (out_matches != NULL && out_capacity > 0) {
    if (matches != NULL) {
      size_t n = match_count < out_capacity ? match_count : out_capacity;
      for (i = 0; i < n; ++i) {
        out_matches[i] = matches[i];
      }
    } else {
      size_t written = 0;
      for (i = 0; i < registry->object_type_count && written < out_capacity; ++i) {
        const steel_registry_object_type_t *object_type = &registry->object_types[i];
        if (object_type_matches_aggregate(object_type, aggregate)) {
          out_matches[written++] = object_type;
        }
      }
    }
  }

  free(matches);
  free(match_indices);
  return total;
}

size_t steel_registry_find_objects_by_aggregate(const steel_registry_t *registry,
                                                const steel_aggregate_type_t *aggregate,
                                                const steel_object_t **out_matches,
                                                size_t out_capacity) {
  const steel_object_t **matches = NULL;
  const steel_registry_object_type_t **match_types = NULL;
  size_t *match_indices = NULL;
  size_t i;
  size_t match_count = 0;
  size_t total = 0;
  if (registry == NULL || aggregate == NULL) {
    return 0;
  }
  if (registry->object_count > 0) {
    matches = (const steel_object_t **)calloc(registry->object_count, sizeof(*matches));
    match_types = (const steel_registry_object_type_t **)calloc(registry->object_count, sizeof(*match_types));
    match_indices = (size_t *)calloc(registry->object_count, sizeof(*match_indices));
  }
  for (i = 0; i < registry->object_count; ++i) {
    const steel_object_t *object = &registry->objects[i];
    const steel_registry_object_type_t *object_type =
        registry_find_object_type_by_name(registry, object->type_name);
    if (!object_type_matches_aggregate(object_type, aggregate)) {
      continue;
    }
    total += 1;
    if (matches != NULL && match_types != NULL && match_indices != NULL) {
      matches[match_count] = object;
      match_types[match_count] = object_type;
      match_indices[match_count] = i;
      match_count += 1;
    }
  }

  if (matches != NULL && match_types != NULL && match_indices != NULL && match_count > 1) {
    size_t a;
    for (a = 0; a + 1 < match_count; ++a) {
      size_t b;
      size_t best = a;
      for (b = a + 1; b < match_count; ++b) {
        int cmp = compare_object_types_for_aggregate(
            match_types[b], match_indices[b], match_types[best], match_indices[best]);
        if (cmp == 0) {
          uint32_t b_handle = matches[b]->receiver_handle;
          uint32_t best_handle = matches[best]->receiver_handle;
          if (b_handle != best_handle) {
            cmp = b_handle < best_handle ? -1 : 1;
          }
        }
        if (cmp < 0) {
          best = b;
        }
      }
      if (best != a) {
        const steel_object_t *tmp_obj = matches[a];
        const steel_registry_object_type_t *tmp_type = match_types[a];
        size_t tmp_index = match_indices[a];
        matches[a] = matches[best];
        match_types[a] = match_types[best];
        match_indices[a] = match_indices[best];
        matches[best] = tmp_obj;
        match_types[best] = tmp_type;
        match_indices[best] = tmp_index;
      }
    }
  }

  if (out_matches != NULL && out_capacity > 0) {
    if (matches != NULL) {
      size_t n = match_count < out_capacity ? match_count : out_capacity;
      for (i = 0; i < n; ++i) {
        out_matches[i] = matches[i];
      }
    } else {
      size_t written = 0;
      for (i = 0; i < registry->object_count && written < out_capacity; ++i) {
        const steel_object_t *object = &registry->objects[i];
        const steel_registry_object_type_t *object_type =
            registry_find_object_type_by_name(registry, object->type_name);
        if (object_type_matches_aggregate(object_type, aggregate)) {
          out_matches[written++] = object;
        }
      }
    }
  }

  free(matches);
  free(match_types);
  free(match_indices);
  return total;
}

int steel_registry_bind_first_matching_object(steel_registry_t *registry,
                                              uint32_t receiver_handle,
                                              const steel_facet_id_t *required_facets,
                                              size_t required_facet_count,
                                              steel_object_t *out_object,
                                              char *err,
                                              size_t err_len) {
  steel_aggregate_type_t aggregate;
  const steel_registry_object_type_t *match = NULL;
  if (registry == NULL || out_object == NULL) {
    write_err(err, err_len, "bind_first_matching_object missing args");
    return -1;
  }
  if (required_facet_count > 0 && required_facets == NULL) {
    write_err(err, err_len, "bind_first_matching_object requires facets");
    return -1;
  }
  aggregate.required_facets = required_facets;
  aggregate.required_facet_count = required_facet_count;
  if (steel_registry_find_object_types_by_aggregate(registry, &aggregate, &match, 1) == 0 || match == NULL ||
      match->name == NULL) {
    write_err(err, err_len, "no plugin object type matches requested aggregate");
    return -1;
  }
  return steel_registry_bind_object(registry, match->name, receiver_handle, out_object, err, err_len);
}

int steel_registry_bind_object(steel_registry_t *registry,
                               const char *object_type_name,
                               uint32_t receiver_handle,
                               steel_object_t *out_object,
                               char *err,
                               size_t err_len) {
  steel_object_t *next;
  char *name_copy;
  if (registry == NULL || registry->plugin == NULL || out_object == NULL) {
    write_err(err, err_len, "registry_bind_object missing args");
    return -1;
  }
  if (registry_find_object_type_by_name(registry, object_type_name) == NULL) {
    write_err(err, err_len, "object type not declared by plugin: %s", object_type_name != NULL ? object_type_name : "<null>");
    return -1;
  }

  if (registry->object_count == registry->object_capacity) {
    size_t cap = registry->object_capacity == 0 ? 8 : registry->object_capacity * 2;
    next = (steel_object_t *)realloc(registry->objects, cap * sizeof(*next));
    if (next == NULL) {
      write_err(err, err_len, "registry object allocation failed");
      return -1;
    }
    registry->objects = next;
    registry->object_capacity = cap;
  }

  name_copy = dup_cstr(object_type_name);
  if (name_copy == NULL) {
    write_err(err, err_len, "registry object name allocation failed");
    return -1;
  }

  registry->objects[registry->object_count].plugin = registry->plugin;
  registry->objects[registry->object_count].receiver_handle = receiver_handle;
  registry->objects[registry->object_count].default_permissions = registry->plugin->granted_permissions;
  registry->objects[registry->object_count].type_name = name_copy;
  *out_object = registry->objects[registry->object_count];
  registry->object_count += 1;

  return 0;
}

int steel_registry_construct_object_typed(steel_registry_t *registry,
                                          const steel_facet_id_t *facet_id,
                                          uint32_t constructor_method_id,
                                          uint32_t permissions,
                                          const steel_typed_value_t *args,
                                          size_t arg_count,
                                          const char *object_type_name,
                                          steel_object_t *out_object,
                                          char *err,
                                          size_t err_len) {
  steel_typed_result_t result;
  int rc;

  if (registry == NULL || registry->plugin == NULL || facet_id == NULL || out_object == NULL) {
    write_err(err, err_len, "registry_construct_object missing args");
    return -1;
  }

  memset(&result, 0, sizeof(result));
  rc = steel_plugin_invoke_typed(registry->plugin,
                                 facet_id,
                                 constructor_method_id,
                                 0,
                                 permissions,
                                 args,
                                 arg_count,
                                 &result,
                                 err,
                                 err_len);
  if (rc != 0) {
    return rc;
  }
  if (result.value.type != STEEL_SIG_TYPE_U32) {
    steel_typed_result_free(&result);
    write_err(err, err_len, "constructor must return U32 handle");
    return -1;
  }

  rc = steel_registry_bind_object(registry, object_type_name, result.value.as.u32, out_object, err, err_len);
  steel_typed_result_free(&result);
  return rc;
}

int steel_registry_invoke_typed(const steel_registry_t *registry,
                                const steel_facet_id_t *facet_id,
                                uint32_t method_id,
                                uint32_t receiver,
                                uint32_t permissions,
                                const steel_typed_value_t *args,
                                size_t arg_count,
                                steel_typed_result_t *result,
                                char *err,
                                size_t err_len) {
  if (registry == NULL || registry->plugin == NULL || facet_id == NULL || result == NULL) {
    write_err(err, err_len, "registry_invoke_typed missing args");
    return -1;
  }
  return steel_plugin_invoke_typed(
      registry->plugin, facet_id, method_id, receiver, permissions, args, arg_count, result, err, err_len);
}

int steel_object_invoke_typed(const steel_object_t *object,
                              const steel_facet_id_t *facet_id,
                              uint32_t method_id,
                              uint32_t permissions,
                              const steel_typed_value_t *args,
                              size_t arg_count,
                              steel_typed_result_t *result,
                              char *err,
                              size_t err_len) {
  const steel_vtable_entry_t *contract;
  steel_typed_value_t *dispatch_args = NULL;
  size_t dispatch_arg_count;
  int prepend_handle = 0;
  int rc;

  if (object == NULL || object->plugin == NULL || facet_id == NULL || result == NULL) {
    write_err(err, err_len, "object_invoke_typed missing args");
    return -1;
  }

  contract = steel_contract_find(facet_id, method_id);
  if (contract == NULL) {
    write_err(err, err_len, "object_invoke_typed unknown facet/method");
    return -1;
  }

  if (contract->steel_fun_signature.param_count > 0 &&
      contract->steel_fun_signature.param_types[0] == STEEL_SIG_TYPE_U32) {
    prepend_handle = 1;
  }

  dispatch_arg_count = contract->steel_fun_signature.param_count;
  if (prepend_handle) {
    if (arg_count + 1 != dispatch_arg_count) {
      write_err(err,
                err_len,
                "object invoke arg mismatch: expected=%zu got=%zu",
                dispatch_arg_count - 1,
                arg_count);
      return -1;
    }
  } else if (arg_count != dispatch_arg_count) {
    write_err(err, err_len, "object invoke arg mismatch: expected=%zu got=%zu", dispatch_arg_count, arg_count);
    return -1;
  }

  if (dispatch_arg_count > 0) {
    dispatch_args = (steel_typed_value_t *)calloc(dispatch_arg_count, sizeof(*dispatch_args));
    if (dispatch_args == NULL) {
      write_err(err, err_len, "object invoke arg allocation failed");
      return -1;
    }

    if (prepend_handle) {
      dispatch_args[0].type = STEEL_SIG_TYPE_U32;
      dispatch_args[0].as.u32 = object->receiver_handle;
      if (arg_count > 0) {
        memcpy(&dispatch_args[1], args, arg_count * sizeof(*args));
      }
    } else if (arg_count > 0) {
      memcpy(dispatch_args, args, arg_count * sizeof(*args));
    }
  }

  rc = steel_plugin_invoke_typed(object->plugin,
                                 facet_id,
                                 method_id,
                                 object->receiver_handle,
                                 permissions,
                                 dispatch_args,
                                 dispatch_arg_count,
                                 result,
                                 err,
                                 err_len);
  free(dispatch_args);
  return rc;
}
