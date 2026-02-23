#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make -s generate-abi-hashes >/dev/null

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

openssl_cflags="$(pkg-config --cflags openssl 2>/dev/null || true)"
openssl_libs="$(pkg-config --libs openssl 2>/dev/null || echo -lcrypto)"
make -s build/libsteel_contracts_builtin.a >/dev/null

cat > "${tmp_dir}/runner.c" <<'SRC'
#include "steel/plugin_host.h"
#include "steel/abi_hashes.h"

#include <stdio.h>
#include <string.h>

static const steel_facet_id_t FACET_DOCUMENT =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                        0x4f, 0xf0);
static const uint32_t METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;

static int ptr_in_plugin_region(const steel_plugin_t *plugin, const uint8_t *ptr, size_t len) {
  const steel_region_block_t *blk = plugin->plugin_region.head;
  while (blk != NULL) {
    const uint8_t *start = blk->data;
    const uint8_t *end = blk->data + blk->capacity;
    if (ptr != NULL && ptr >= start && (len == 0 || ptr + len <= end)) {
      return 1;
    }
    blk = blk->next;
  }
  return 0;
}

int main(int argc, char **argv) {
  steel_policy_t policy;
  steel_plugin_t plugin;
  steel_result_t result;
  steel_call_t call;
  steel_engine_vtable_t engine;
  char err[256];
  uint8_t payload[] = "hello from host";

  if (argc != 2) {
    fprintf(stderr, "usage: %s <plugin.component.wasm>\n", argv[0]);
    return 2;
  }

  memset(&policy, 0, sizeof(policy));
  memset(&plugin, 0, sizeof(plugin));
  memset(&result, 0, sizeof(result));
  memset(&call, 0, sizeof(call));

  policy.expected_layout_hash = STEEL_EXPECTED_LAYOUT_HASH;
  policy.expected_type_table_hash = STEEL_EXPECTED_TYPE_TABLE_HASH;
  policy.min_abi_minor = 0;
  policy.max_memory_pages = 64;
  policy.trusted_attestation_public_key_path = "plugins/echo-plugin/keys/demo_public.pem";
  policy.required_signer_id = "demo-dev";

  engine = steel_wasmtime_component_engine();

  if (steel_plugin_load(&plugin, argv[1], &policy, &engine, err, sizeof(err)) != 0) {
    fprintf(stderr, "plugin load failed: %s\n", err);
    return 3;
  }

  call.facet_id = FACET_DOCUMENT;
  call.method_id = METHOD_ID_DOCUMENT_APPEND;
  call.receiver_handle = 42;
  call.input = payload;
  call.input_len = strlen((const char *)payload);

  if (steel_plugin_invoke(&plugin, &call, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "invoke failed: %s\n", err);
    steel_plugin_unload(&plugin);
    return 4;
  }

  if (result.output_len != strlen((const char *)payload) || memcmp(result.output, payload, result.output_len) != 0) {
    fprintf(stderr, "unexpected output payload\n");
    steel_result_free(&result);
    steel_plugin_unload(&plugin);
    return 5;
  }

  if (ptr_in_plugin_region(&plugin, result.output, result.output_len)) {
    fprintf(stderr, "isolation failure: host output points into plugin region\n");
    steel_result_free(&result);
    steel_plugin_unload(&plugin);
    return 6;
  }

  steel_result_free(&result);
  if (result.storage.head != NULL) {
    fprintf(stderr, "region lifetime failure: result storage not destroyed\n");
    steel_plugin_unload(&plugin);
    return 7;
  }

  steel_plugin_unload(&plugin);
  printf("memory isolation + region lifetime checks passed\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c src/engine_wasmtime_component.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.component.wasm
