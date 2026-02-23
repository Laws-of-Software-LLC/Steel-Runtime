#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make -s build/libsteel_contracts_builtin.a >/dev/null
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

#include <stdio.h>
#include <string.h>

static const steel_facet_id_t FACET_DOCUMENT =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                        0x4f, 0xf0);
static const uint32_t METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;

int main(int argc, char **argv) {
  steel_policy_t policy;
  steel_plugin_t plugin;
  steel_engine_vtable_t engine;
  steel_typed_value_t args[2];
  steel_typed_result_t result;
  char err[256];
  const uint8_t payload[] = "hello";

  if (argc != 2) {
    fprintf(stderr, "usage: %s <plugin.component.wasm>\n", argv[0]);
    return 2;
  }

  memset(&policy, 0, sizeof(policy));
  memset(&plugin, 0, sizeof(plugin));
  memset(&result, 0, sizeof(result));
  memset(args, 0, sizeof(args));

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

  args[0].type = STEEL_SIG_TYPE_U32;
  args[0].as.u32 = 42u;
  args[1].type = STEEL_SIG_TYPE_BYTES;
  args[1].as.bytes.ptr = payload;
  args[1].as.bytes.len = sizeof(payload) - 1;

  if (steel_plugin_invoke_typed(&plugin,
                                &FACET_DOCUMENT,
                                METHOD_ID_DOCUMENT_APPEND,
                                42,
                                0,
                                args,
                                2,
                                &result,
                                err,
                                sizeof(err)) != 0) {
    fprintf(stderr, "typed invoke failed: %s\n", err);
    steel_plugin_unload(&plugin);
    return 1;
  }

  if (result.value.type != STEEL_SIG_TYPE_BYTES) {
    fprintf(stderr, "unexpected typed result kind=%u\n", (unsigned)result.value.type);
    steel_typed_result_free(&result);
    steel_plugin_unload(&plugin);
    return 3;
  }

  if (result.value.as.bytes.ptr == NULL || result.value.as.bytes.len != (sizeof(payload) - 1)) {
    fprintf(stderr, "unexpected marshalled payload length=%zu\n", result.value.as.bytes.len);
    steel_typed_result_free(&result);
    steel_plugin_unload(&plugin);
    return 4;
  }

  if (memcmp(result.value.as.bytes.ptr, payload, sizeof(payload) - 1) != 0) {
    fprintf(stderr, "automatic typed invocation result mismatch\n");
    steel_typed_result_free(&result);
    steel_plugin_unload(&plugin);
    return 5;
  }

  steel_typed_result_free(&result);
  steel_plugin_unload(&plugin);
  printf("typed invoke auto-marshalling works\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c src/engine_wasmtime_component.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.component.wasm
