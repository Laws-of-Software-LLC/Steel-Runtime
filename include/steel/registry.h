#ifndef STEEL_REGISTRY_H
#define STEEL_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

#include "steel/plugin_host.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct steel_registry_method {
  uint32_t method_id;
  const char *method_name;
  steel_fun_signature_t signature;
} steel_registry_method_t;

typedef struct steel_registry_facet {
  steel_facet_id_t facet_id;
  const steel_registry_method_t *methods;
  size_t method_count;
} steel_registry_facet_t;

typedef struct steel_registry_object_type {
  const char *name;
  const steel_facet_id_t *facets;
  size_t facet_count;
} steel_registry_object_type_t;

typedef struct steel_aggregate_type {
  const steel_facet_id_t *required_facets;
  size_t required_facet_count;
} steel_aggregate_type_t;

typedef struct steel_object {
  steel_plugin_t *plugin;
  uint32_t receiver_handle;
  uint32_t default_permissions;
  const char *type_name;
} steel_object_t;

typedef struct steel_registry {
  steel_plugin_t *plugin;
  steel_registry_facet_t *facets;
  size_t facet_count;
  steel_registry_method_t *methods;
  size_t method_count;
  steel_registry_object_type_t *object_types;
  size_t object_type_count;
  steel_object_t *objects;
  size_t object_count;
  size_t object_capacity;
} steel_registry_t;

void steel_registry_init(steel_registry_t *registry);
void steel_registry_free(steel_registry_t *registry);
int steel_registry_build(steel_plugin_t *plugin, steel_registry_t *registry, char *err, size_t err_len);

size_t steel_registry_facet_count(const steel_registry_t *registry);
const steel_registry_facet_t *steel_registry_facet_get(const steel_registry_t *registry, size_t idx);

size_t steel_registry_object_count(const steel_registry_t *registry);
const steel_object_t *steel_registry_object_get(const steel_registry_t *registry, size_t idx);
size_t steel_registry_object_type_count(const steel_registry_t *registry);
const steel_registry_object_type_t *steel_registry_object_type_get(const steel_registry_t *registry, size_t idx);
size_t steel_registry_find_object_types_by_aggregate(const steel_registry_t *registry,
                                                     const steel_aggregate_type_t *aggregate,
                                                     const steel_registry_object_type_t **out_matches,
                                                     size_t out_capacity);
size_t steel_registry_find_objects_by_aggregate(const steel_registry_t *registry,
                                                const steel_aggregate_type_t *aggregate,
                                                const steel_object_t **out_matches,
                                                size_t out_capacity);
int steel_registry_bind_first_matching_object(steel_registry_t *registry,
                                              uint32_t receiver_handle,
                                              const steel_facet_id_t *required_facets,
                                              size_t required_facet_count,
                                              steel_object_t *out_object,
                                              char *err,
                                              size_t err_len);
int steel_registry_bind_object(steel_registry_t *registry,
                               const char *object_type_name,
                               uint32_t receiver_handle,
                               steel_object_t *out_object,
                               char *err,
                               size_t err_len);
int steel_registry_construct_object_typed(steel_registry_t *registry,
                                          const steel_facet_id_t *facet_id,
                                          uint32_t constructor_method_id,
                                          uint32_t permissions,
                                          const steel_typed_value_t *args,
                                          size_t arg_count,
                                          const char *object_type_name,
                                          steel_object_t *out_object,
                                          char *err,
                                          size_t err_len);
int steel_registry_invoke_typed(const steel_registry_t *registry,
                                const steel_facet_id_t *facet_id,
                                uint32_t method_id,
                                uint32_t receiver,
                                uint32_t permissions,
                                const steel_typed_value_t *args,
                                size_t arg_count,
                                steel_typed_result_t *result,
                                char *err,
                                size_t err_len);

int steel_object_invoke_typed(const steel_object_t *object,
                              const steel_facet_id_t *facet_id,
                              uint32_t method_id,
                              uint32_t permissions,
                              const steel_typed_value_t *args,
                              size_t arg_count,
                              steel_typed_result_t *result,
                              char *err,
                              size_t err_len);

#define STEEL_REGISTRY_PP_NARG_(...) STEEL_REGISTRY_PP_ARG_N(__VA_ARGS__)
#define STEEL_REGISTRY_PP_ARG_N(_1,  _2,  _3,  _4,  _5,  _6,  _7,  _8, \
                                _9,  _10, _11, _12, _13, _14, _15, _16, N, ...) N
#define STEEL_REGISTRY_PP_RSEQ_N() \
  16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
#define STEEL_REGISTRY_PP_NARG(...) STEEL_REGISTRY_PP_NARG_(__VA_ARGS__, STEEL_REGISTRY_PP_RSEQ_N())

#define STEEL_REGISTRY_BIND_OBJECT_BY_FACETS(registry, receiver_handle, out_object, err, err_len, ...)              \
  ((steel_registry_bind_first_matching_object((registry),                                                            \
                                              (receiver_handle),                                                     \
                                              (steel_facet_id_t[]){__VA_ARGS__},                                    \
                                              STEEL_REGISTRY_PP_NARG(__VA_ARGS__),                                  \
                                              (out_object),                                                          \
                                              (err),                                                                 \
                                              (err_len)) == 0)                                                       \
       ? (out_object)                                                                                                 \
       : NULL)

#ifdef __cplusplus
}
#endif

#endif
