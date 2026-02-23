#ifndef STEEL_PROXY_H
#define STEEL_PROXY_H

#include <stddef.h>
#include <stdint.h>

#include "steel/plugin_host.h"
#include "steel/registry.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const steel_facet_id_t STEEL_FACET_LOGGER_ID;
extern const steel_facet_id_t STEEL_FACET_DOCUMENT_ID;

extern const uint32_t STEEL_METHOD_ID_LOG_INFO;
extern const uint32_t STEEL_METHOD_ID_DOCUMENT_APPEND;

typedef struct steel_proxy_bytes {
  uint8_t *ptr;
  size_t len;
} steel_proxy_bytes_t;

void steel_proxy_bytes_free(steel_proxy_bytes_t *bytes);

int steel_proxy_log_info(steel_plugin_t *plugin,
                         uint32_t receiver_handle,
                         uint32_t permissions,
                         steel_bytes_view_t message,
                         char *err,
                         size_t err_len);

int steel_proxy_object_log_info(const steel_object_t *object,
                                steel_bytes_view_t message,
                                char *err,
                                size_t err_len);

int steel_proxy_document_append(steel_plugin_t *plugin,
                                uint32_t receiver_handle,
                                uint32_t permissions,
                                uint32_t receiver_arg,
                                steel_bytes_view_t payload,
                                steel_proxy_bytes_t *out_result,
                                char *err,
                                size_t err_len);

int steel_proxy_object_document_append(const steel_object_t *object,
                                       steel_bytes_view_t payload,
                                       steel_proxy_bytes_t *out_result,
                                       char *err,
                                       size_t err_len);

#ifdef __cplusplus
}
#endif

#endif
