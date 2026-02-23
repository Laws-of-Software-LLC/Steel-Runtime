#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make -s build/libsteel_contracts_builtin.a >/dev/null
make -s generate-proxies >/dev/null
make -s generate-abi-hashes >/dev/null

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

openssl_cflags="$(pkg-config --cflags openssl 2>/dev/null || true)"
openssl_libs="$(pkg-config --libs openssl 2>/dev/null || echo -lcrypto)"

cat > "${tmp_dir}/runner.c" <<'SRC'
#include "steel/plugin_host.h"
#include "steel/abi_hashes.h"
#include "steel/proxy.h"
#include "steel/proxy_generated.h"
#include "steel/registry.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  steel_policy_t policy;
  steel_plugin_t plugin;
  steel_registry_t registry;
  steel_object_t object;
  steel_aggregate_type_t document_aggregate;
  steel_facet_id_t required_facets[1];
  const steel_registry_object_type_t *matches[4];
  size_t match_count;
  const steel_registry_object_type_t *object_type;
  steel_proxy_bytes_t result;
  steel_proxy_bytes_t gen_result;
  steel_engine_vtable_t engine;
  char err[256];
  const uint8_t payload[] = "hello via proxy";
  steel_bytes_view_t payload_view;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <plugin.component.wasm>\n", argv[0]);
    return 2;
  }

  memset(&policy, 0, sizeof(policy));
  memset(&plugin, 0, sizeof(plugin));
  memset(&registry, 0, sizeof(registry));
  memset(&object, 0, sizeof(object));
  memset(&result, 0, sizeof(result));
  memset(&gen_result, 0, sizeof(gen_result));
  payload_view.ptr = payload;
  payload_view.len = sizeof(payload) - 1;

  policy.expected_layout_hash = STEEL_EXPECTED_LAYOUT_HASH;
  policy.expected_type_table_hash = STEEL_EXPECTED_TYPE_TABLE_HASH;
  policy.min_abi_minor = 0;
  policy.max_memory_pages = 64;
  policy.default_plugin_region_bytes = STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  policy.max_plugin_region_bytes = 256 * 1024;
  policy.allowed_plugin_permissions = 0;
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
  required_facets[0] = STEEL_FACET_DOCUMENT_ID;
  document_aggregate.required_facets = required_facets;
  document_aggregate.required_facet_count = 1;
  match_count = steel_registry_find_object_types_by_aggregate(
      &registry, &document_aggregate, matches, sizeof(matches) / sizeof(matches[0]));
  if (match_count != 1) {
    fprintf(stderr, "expected one aggregate match, got %zu\n", match_count);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }
  object_type = matches[0];
  if (object_type == NULL || object_type->name == NULL) {
    fprintf(stderr, "plugin did not declare object types\n");
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }
  if (steel_registry_bind_object(&registry, object_type->name, 42, &object, err, sizeof(err)) != 0) {
    fprintf(stderr, "bind object failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }

  if (steel_proxy_object_log_info(&object, payload_view, err, sizeof(err)) != 0) {
    fprintf(stderr, "proxy log.info failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }

  if (steel_proxy_object_document_append(&object, payload_view, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "proxy document.append failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }

  if (result.len != sizeof(payload) - 1 || memcmp(result.ptr, payload, sizeof(payload) - 1) != 0) {
    fprintf(stderr, "unexpected proxy result bytes\n");
    steel_proxy_bytes_free(&result);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 4;
  }
  steel_proxy_bytes_free(&result);
  if (steel_object_proxy_gen_document_document_append(&object, payload_view, &gen_result, err, sizeof(err)) != 0) {
    fprintf(stderr, "generated proxy document.append failed: %s\n", err);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 1;
  }
  if (gen_result.len != sizeof(payload) - 1 || memcmp(gen_result.ptr, payload, sizeof(payload) - 1) != 0) {
    fprintf(stderr, "unexpected generated proxy result bytes\n");
    steel_proxy_bytes_free(&gen_result);
    steel_registry_free(&registry);
    steel_plugin_unload(&plugin);
    return 5;
  }
  steel_proxy_bytes_free(&gen_result);

  steel_registry_free(&registry);
  steel_plugin_unload(&plugin);
  printf("proxy API works\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude -Ibuild/generated/include \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c src/registry.c src/proxy.c src/engine_wasmtime_component.c \
  build/generated/src/proxy_generated.c "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.component.wasm
