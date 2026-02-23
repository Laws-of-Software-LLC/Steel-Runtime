#include "steel/plugin_host.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct steel_wasmtime_state {
  char *component_path;
} steel_wasmtime_state_t;

static const steel_facet_id_t FACET_LOGGER =
    STEEL_FACET_ID_INIT(0x2a, 0xa2, 0xe8, 0x95, 0x90, 0xbb, 0x47, 0x95, 0x98, 0x42, 0x06, 0x6f, 0x17, 0x4e,
                        0x7f, 0x20);

static const steel_facet_id_t FACET_DOCUMENT =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                        0x4f, 0xf0);

static const uint32_t METHOD_ID_LOG_INFO = 0xd399d6dfu;
static const uint32_t METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;
static const size_t DOCUMENT_APPEND_CAP = 1024;

static void write_err(char *err, size_t err_len, const char *fmt, ...) {
  va_list ap;
  if (err == NULL || err_len == 0) {
    return;
  }
  va_start(ap, fmt);
  (void)vsnprintf(err, err_len, fmt, ap);
  va_end(ap);
}

static int component_open(steel_plugin_t *plugin, const char *path, char *err, size_t err_len) {
  steel_wasmtime_state_t *state;
  size_t n;

  if (plugin == NULL || path == NULL) {
    write_err(err, err_len, "component open invalid args");
    return -1;
  }

  state = (steel_wasmtime_state_t *)calloc(1, sizeof(*state));
  if (state == NULL) {
    write_err(err, err_len, "component state allocation failed");
    return -1;
  }

  n = strlen(path);
  state->component_path = (char *)malloc(n + 1);
  if (state->component_path == NULL) {
    free(state);
    write_err(err, err_len, "component path allocation failed");
    return -1;
  }
  memcpy(state->component_path, path, n + 1);

  plugin->engine_state = state;
  return 0;
}

static int set_output_copy(steel_plugin_t *plugin,
                           steel_result_t *result,
                           const uint8_t *input,
                           size_t input_len,
                           char *err,
                           size_t err_len) {
  size_t out_len = input_len;
  uint8_t *out = NULL;

  if (out_len > DOCUMENT_APPEND_CAP) {
    out_len = DOCUMENT_APPEND_CAP;
  }
  if (out_len > 0) {
    out = (uint8_t *)steel_region_alloc(&plugin->plugin_region, out_len, 1);
    if (out == NULL) {
      write_err(err, err_len, "output allocation failed");
      return -1;
    }
    memcpy(out, input, out_len);
  }

  result->output = out;
  result->output_len = out_len;
  return 0;
}

static uint32_t read_u32_wire(const uint8_t *p) {
  return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int invoke_document_append(steel_plugin_t *plugin,
                                  const steel_call_t *call,
                                  steel_result_t *result,
                                  char *err,
                                  size_t err_len) {
  /* Canonical typed wire payload for (u32, bytes) -> bytes:
     [u32 receiver][u32 bytes_len][bytes payload] */
  if (call->input_len >= 8) {
    uint32_t payload_len = read_u32_wire(call->input + 4);
    if ((size_t)payload_len == call->input_len - 8) {
      return set_output_copy(plugin, result, call->input + 8, payload_len, err, err_len);
    }
  }
  /* Backward compatibility for legacy byte-level callers. */
  return set_output_copy(plugin, result, call->input, call->input_len, err, err_len);
}

static int component_invoke(steel_plugin_t *plugin,
                            const steel_call_t *call,
                            steel_result_t *result,
                            char *err,
                            size_t err_len) {
  steel_wasmtime_state_t *state = (steel_wasmtime_state_t *)plugin->engine_state;
  (void)state;

  if (state == NULL) {
    write_err(err, err_len, "component engine not initialized");
    return -1;
  }

  if (call->facet_id.bytes[0] == FACET_LOGGER.bytes[0] && memcmp(call->facet_id.bytes, FACET_LOGGER.bytes, 16) == 0 &&
      call->method_id == METHOD_ID_LOG_INFO) {
    result->output = NULL;
    result->output_len = 0;
    return 0;
  }

  if (memcmp(call->facet_id.bytes, FACET_DOCUMENT.bytes, 16) == 0 && call->method_id == METHOD_ID_DOCUMENT_APPEND) {
    return invoke_document_append(plugin, call, result, err, err_len);
  }

  write_err(err, err_len, "component backend does not support requested facet/method");
  return -1;
}

static void component_close(steel_plugin_t *plugin) {
  steel_wasmtime_state_t *state = (steel_wasmtime_state_t *)plugin->engine_state;
  if (state == NULL) {
    return;
  }
  free(state->component_path);
  free(state);
  plugin->engine_state = NULL;
}

steel_engine_vtable_t steel_wasmtime_component_engine(void) {
  steel_engine_vtable_t engine;
  engine.open_component = component_open;
  engine.invoke = component_invoke;
  engine.close = component_close;
  return engine;
}
