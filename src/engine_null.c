#include "steel/plugin_host.h"

#include <stdarg.h>
#include <stdio.h>
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

static int null_open(steel_plugin_t *plugin, const char *path, char *err, size_t err_len) {
  (void)plugin;
  (void)path;
  write_err(err, err_len, "no sandbox engine configured (rebuild with STEEL_ENABLE_WASMTIME)");
  return -1;
}

static int null_invoke(steel_plugin_t *plugin,
                       const steel_call_t *call,
                       steel_result_t *result,
                       char *err,
                       size_t err_len) {
  (void)plugin;
  (void)call;
  (void)result;
  write_err(err, err_len, "no sandbox engine configured");
  return -1;
}

static void null_close(steel_plugin_t *plugin) { (void)plugin; }

steel_engine_vtable_t steel_null_engine(void) {
  steel_engine_vtable_t engine;
  engine.open_component = null_open;
  engine.invoke = null_invoke;
  engine.close = null_close;
  return engine;
}
