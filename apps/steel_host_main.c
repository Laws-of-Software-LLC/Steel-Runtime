#include "steel/plugin_host.h"
#include "steel/policy_config.h"
#include "steel/proxy.h"
#include "steel/proxy_generated.h"
#include "steel/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  steel_policy_t policy;
  steel_plugin_t plugin;
  steel_registry_t registry;
  steel_object_t document;
  steel_proxy_bytes_t result;
  steel_engine_vtable_t engine;
  char err[256];
  const char *path;
  uint8_t payload[] = "hello from host";
  steel_bytes_view_t payload_view;

  if (argc < 2) {
    fprintf(stderr, "usage: %s <plugin.component.wasm>\n", argv[0]);
    return 2;
  }

  path = argv[1];
  payload_view.ptr = payload;
  payload_view.len = strlen((const char *)payload);

  steel_policy_apply_compile_time(&policy);
  steel_registry_init(&registry);

  engine = steel_wasmtime_component_engine();

  if (steel_plugin_load(&plugin, path, &policy, &engine, err, sizeof(err)) != 0) {
    fprintf(stderr, "plugin load failed: %s\n", err);
    return 1;
  }
  if (steel_registry_build(&plugin, &registry, err, sizeof(err)) != 0) {
    fprintf(stderr, "registry build failed: %s\n", err);
    steel_plugin_unload(&plugin);
    return 1;
  }
  if (STEEL_REGISTRY_BIND_OBJECT_BY_FACETS(&registry, 42, &document, err, sizeof(err), STEEL_FACET_DOCUMENT_ID) ==
      NULL) {
    fprintf(stderr, "registry bind object failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }

  memset(&result, 0, sizeof(result));
  if (steel_object_proxy_gen_document_document_append(&document, payload_view, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "proxy invoke failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }

  printf("plugin output bytes: %zu\n", result.len);
  if (result.len > 0) {
    fwrite(result.ptr, 1, result.len, stdout);
    fputc('\n', stdout);
  }

  steel_proxy_bytes_free(&result);
  steel_registry_free(&registry);
  steel_plugin_unload(&plugin);
  return 0;
}
