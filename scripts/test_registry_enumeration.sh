#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make -s build/libsteel_contracts_builtin.a >/dev/null
make -s generate-abi-hashes >/dev/null

openssl_cflags="$(pkg-config --cflags openssl 2>/dev/null || true)"
openssl_libs="$(pkg-config --libs openssl 2>/dev/null || echo -lcrypto)"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cat > "${tmp_dir}/runner.c" <<'SRC'
#include "steel/plugin_host.h"
#include "steel/abi_hashes.h"
#include "steel/proxy.h"
#include "steel/registry.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  steel_policy_t policy;
  steel_plugin_t plugin;
  steel_registry_t registry;
  steel_object_t doc;
  steel_aggregate_type_t doc_aggregate;
  steel_facet_id_t required_facets[1];
  const steel_registry_object_type_t *matches[4];
  size_t match_count;
  const steel_registry_object_type_t *doc_type;
  steel_typed_result_t result;
  steel_typed_value_t args[1];
  steel_engine_vtable_t engine;
  steel_bytes_view_t payload;
  char err[256];
  uint8_t message[] = "hello registry";
  size_t i;
  int found_document_method = 0;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <plugin.component.wasm>\n", argv[0]);
    return 2;
  }

  memset(&policy, 0, sizeof(policy));
  memset(&plugin, 0, sizeof(plugin));
  memset(&registry, 0, sizeof(registry));
  memset(&result, 0, sizeof(result));
  memset(args, 0, sizeof(args));

  policy.expected_layout_hash = STEEL_EXPECTED_LAYOUT_HASH;
  policy.expected_type_table_hash = STEEL_EXPECTED_TYPE_TABLE_HASH;
  policy.min_abi_minor = 0;
  policy.max_memory_pages = 64;
  policy.default_plugin_region_bytes = STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  policy.max_plugin_region_bytes = 256 * 1024;
  policy.trusted_attestation_public_key_path = "plugins/echo-plugin/keys/demo_public.pem";
  policy.required_signer_id = "demo-dev";

  engine = steel_wasmtime_component_engine();
  if (steel_plugin_load(&plugin, argv[1], &policy, &engine, err, sizeof(err)) != 0) {
    fprintf(stderr, "plugin load failed: %s\n", err);
    return 1;
  }

  steel_registry_init(&registry);
  if (steel_registry_build(&plugin, &registry, err, sizeof(err)) != 0) {
    fprintf(stderr, "registry build failed: %s\n", err);
    steel_plugin_unload(&plugin);
    return 1;
  }

  if (steel_registry_facet_count(&registry) < 2) {
    fprintf(stderr, "expected at least two facets, got %zu\n", steel_registry_facet_count(&registry));
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 2;
  }
  required_facets[0] = STEEL_FACET_DOCUMENT_ID;
  doc_aggregate.required_facets = required_facets;
  doc_aggregate.required_facet_count = 1;
  match_count = steel_registry_find_object_types_by_aggregate(
      &registry, &doc_aggregate, matches, sizeof(matches) / sizeof(matches[0]));
  if (match_count < 1) {
    fprintf(stderr, "expected at least one aggregate object type match\n");
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 2;
  }

  for (i = 0; i < steel_registry_facet_count(&registry); ++i) {
    const steel_registry_facet_t *facet = steel_registry_facet_get(&registry, i);
    size_t j;
    if (facet == NULL) {
      continue;
    }
    for (j = 0; j < facet->method_count; ++j) {
      if (facet->methods[j].method_id == STEEL_METHOD_ID_DOCUMENT_APPEND) {
        found_document_method = 1;
      }
    }
  }
  if (!found_document_method) {
    fprintf(stderr, "document.append method not found in registry\n");
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 3;
  }

  doc_type = matches[0];
  if (doc_type == NULL || doc_type->name == NULL) {
    fprintf(stderr, "object type missing\n");
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 4;
  }
  if (steel_registry_bind_object(&registry, doc_type->name, 42, &doc, err, sizeof(err)) != 0) {
    fprintf(stderr, "bind object failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 4;
  }

  payload.ptr = message;
  payload.len = strlen((const char *)message);
  args[0].type = STEEL_SIG_TYPE_BYTES;
  args[0].as.bytes = payload;

  if (steel_object_invoke_typed(&doc,
                                &STEEL_FACET_DOCUMENT_ID,
                                STEEL_METHOD_ID_DOCUMENT_APPEND,
                                0,
                                args,
                                1,
                                &result,
                                err,
                                sizeof(err)) != 0) {
    fprintf(stderr, "object invoke failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 5;
  }

  if (result.value.type != STEEL_SIG_TYPE_BYTES || result.value.as.bytes.len != payload.len ||
      memcmp(result.value.as.bytes.ptr, payload.ptr, payload.len) != 0) {
    fprintf(stderr, "unexpected object invoke result\n");
    steel_typed_result_free(&result);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 6;
  }

  steel_typed_result_free(&result);
  steel_registry_free(&registry);
  steel_plugin_unload(&plugin);
  printf("registry facet enumeration + object invocation works\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c src/registry.c src/proxy.c src/engine_wasmtime_component.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.component.wasm
