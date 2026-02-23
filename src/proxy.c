#include "steel/proxy.h"

#include <stdlib.h>
#include <string.h>

const steel_facet_id_t STEEL_FACET_LOGGER_ID =
    STEEL_FACET_ID_INIT(0x2a, 0xa2, 0xe8, 0x95, 0x90, 0xbb, 0x47, 0x95, 0x98, 0x42, 0x06, 0x6f, 0x17, 0x4e, 0x7f,
                        0x20);

const steel_facet_id_t STEEL_FACET_DOCUMENT_ID =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99, 0x4f,
                        0xf0);

const uint32_t STEEL_METHOD_ID_LOG_INFO = 0xd399d6dfu;
const uint32_t STEEL_METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;

static int copy_bytes_result(const steel_typed_result_t *result, steel_proxy_bytes_t *out_result) {
  if (result == NULL || out_result == NULL) {
    return -1;
  }
  out_result->ptr = NULL;
  out_result->len = 0;
  if (result->value.as.bytes.len == 0) {
    return 0;
  }
  out_result->ptr = (uint8_t *)malloc(result->value.as.bytes.len);
  if (out_result->ptr == NULL) {
    return -1;
  }
  memcpy(out_result->ptr, result->value.as.bytes.ptr, result->value.as.bytes.len);
  out_result->len = result->value.as.bytes.len;
  return 0;
}

void steel_proxy_bytes_free(steel_proxy_bytes_t *bytes) {
  if (bytes == NULL) {
    return;
  }
  free(bytes->ptr);
  bytes->ptr = NULL;
  bytes->len = 0;
}

int steel_proxy_log_info(steel_plugin_t *plugin,
                         uint32_t receiver_handle,
                         uint32_t permissions,
                         steel_bytes_view_t message,
                         char *err,
                         size_t err_len) {
  steel_typed_result_t result;
  steel_typed_value_t args[1];
  int rc;

  memset(&result, 0, sizeof(result));
  memset(args, 0, sizeof(args));
  args[0].type = STEEL_SIG_TYPE_BYTES;
  args[0].as.bytes = message;

  rc = steel_plugin_invoke_typed(plugin,
                                 &STEEL_FACET_LOGGER_ID,
                                 STEEL_METHOD_ID_LOG_INFO,
                                 receiver_handle,
                                 permissions,
                                 args,
                                 1,
                                 &result,
                                 err,
                                 err_len);
  if (rc != 0) {
    return rc;
  }
  if (result.value.type != STEEL_SIG_TYPE_VOID) {
    steel_typed_result_free(&result);
    return -1;
  }
  steel_typed_result_free(&result);
  return 0;
}

int steel_proxy_object_log_info(const steel_object_t *object,
                                steel_bytes_view_t message,
                                char *err,
                                size_t err_len) {
  steel_typed_result_t result;
  steel_typed_value_t args[1];
  int rc;

  if (object == NULL) {
    return -1;
  }

  memset(&result, 0, sizeof(result));
  memset(args, 0, sizeof(args));
  args[0].type = STEEL_SIG_TYPE_BYTES;
  args[0].as.bytes = message;

  rc = steel_object_invoke_typed(
      object, &STEEL_FACET_LOGGER_ID, STEEL_METHOD_ID_LOG_INFO, object->default_permissions, args, 1, &result, err, err_len);
  if (rc != 0) {
    return rc;
  }
  if (result.value.type != STEEL_SIG_TYPE_VOID) {
    steel_typed_result_free(&result);
    return -1;
  }
  steel_typed_result_free(&result);
  return 0;
}

int steel_proxy_document_append(steel_plugin_t *plugin,
                                uint32_t receiver_handle,
                                uint32_t permissions,
                                uint32_t receiver_arg,
                                steel_bytes_view_t payload,
                                steel_proxy_bytes_t *out_result,
                                char *err,
                                size_t err_len) {
  steel_typed_result_t result;
  steel_typed_value_t args[2];
  int rc;

  if (out_result == NULL) {
    return -1;
  }

  memset(&result, 0, sizeof(result));
  memset(args, 0, sizeof(args));
  args[0].type = STEEL_SIG_TYPE_U32;
  args[0].as.u32 = receiver_arg;
  args[1].type = STEEL_SIG_TYPE_BYTES;
  args[1].as.bytes = payload;

  rc = steel_plugin_invoke_typed(plugin,
                                 &STEEL_FACET_DOCUMENT_ID,
                                 STEEL_METHOD_ID_DOCUMENT_APPEND,
                                 receiver_handle,
                                 permissions,
                                 args,
                                 2,
                                 &result,
                                 err,
                                 err_len);
  if (rc != 0) {
    return rc;
  }
  if (result.value.type != STEEL_SIG_TYPE_BYTES) {
    steel_typed_result_free(&result);
    return -1;
  }
  rc = copy_bytes_result(&result, out_result);
  steel_typed_result_free(&result);
  return rc;
}

int steel_proxy_object_document_append(const steel_object_t *object,
                                       steel_bytes_view_t payload,
                                       steel_proxy_bytes_t *out_result,
                                       char *err,
                                       size_t err_len) {
  steel_typed_result_t result;
  steel_typed_value_t args[1];
  int rc;

  if (object == NULL || out_result == NULL) {
    return -1;
  }

  memset(&result, 0, sizeof(result));
  memset(args, 0, sizeof(args));
  args[0].type = STEEL_SIG_TYPE_BYTES;
  args[0].as.bytes = payload;

  rc = steel_object_invoke_typed(
      object,
      &STEEL_FACET_DOCUMENT_ID,
      STEEL_METHOD_ID_DOCUMENT_APPEND,
      object->default_permissions,
      args,
      1,
      &result,
      err,
      err_len);
  if (rc != 0) {
    return rc;
  }
  if (result.value.type != STEEL_SIG_TYPE_BYTES) {
    steel_typed_result_free(&result);
    return -1;
  }
  rc = copy_bytes_result(&result, out_result);
  steel_typed_result_free(&result);
  return rc;
}
