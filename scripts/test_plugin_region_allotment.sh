#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

make plugin >/dev/null
make -s generate-abi-hashes >/dev/null

cd plugins/echo-plugin
cargo component build --release >/dev/null
wasm_path=""
for candidate in \
  "target/wasm32-wasip1/release/steel_echo_plugin.wasm" \
  "target/wasm32-wasi/release/steel_echo_plugin.wasm"; do
  if [[ -f "${candidate}" ]]; then
    wasm_path="${candidate}"
    break
  fi
done
if [[ -z "${wasm_path}" ]]; then
  echo "error: could not find built component wasm" >&2
  exit 1
fi
python3 scripts/embed_manifest.py --requested-region-bytes 16384 "${wasm_path}" dist/steel-echo-plugin.region16k.component.wasm
cd "${repo_dir}"

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
#include <stdlib.h>
#include <string.h>

static const steel_facet_id_t FACET_DOCUMENT =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                        0x4f, 0xf0);
static const uint32_t METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;

int main(int argc, char **argv) {
  steel_policy_t policy;
  steel_plugin_t plugin;
  steel_result_t result;
  steel_call_t call;
  steel_engine_vtable_t engine;
  char err[256];
  uint8_t *payload = NULL;
  size_t payload_len;

  if (argc != 4) {
    fprintf(stderr, "usage: %s <plugin.component.wasm> <max_region_bytes> <payload_len>\n", argv[0]);
    return 2;
  }

  payload_len = (size_t)strtoul(argv[3], NULL, 10);
  payload = (uint8_t *)malloc(payload_len);
  if (payload == NULL) {
    fprintf(stderr, "payload allocation failed\n");
    return 3;
  }
  memset(payload, 'a', payload_len);

  memset(&policy, 0, sizeof(policy));
  memset(&plugin, 0, sizeof(plugin));
  memset(&result, 0, sizeof(result));
  memset(&call, 0, sizeof(call));

  policy.expected_layout_hash = STEEL_EXPECTED_LAYOUT_HASH;
  policy.expected_type_table_hash = STEEL_EXPECTED_TYPE_TABLE_HASH;
  policy.min_abi_minor = 0;
  policy.max_memory_pages = 64;
  policy.default_plugin_region_bytes = STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  policy.max_plugin_region_bytes = (uint32_t)strtoul(argv[2], NULL, 10);
  policy.trusted_attestation_public_key_path = "plugins/echo-plugin/keys/demo_public.pem";
  policy.required_signer_id = "demo-dev";

  engine = steel_wasmtime_component_engine();
  if (steel_plugin_load(&plugin, argv[1], &policy, &engine, err, sizeof(err)) != 0) {
    fprintf(stderr, "plugin load failed: %s\n", err);
    free(payload);
    return 4;
  }

  call.facet_id = FACET_DOCUMENT;
  call.method_id = METHOD_ID_DOCUMENT_APPEND;
  call.receiver_handle = 42;
  call.permissions = 0;
  call.input = payload;
  call.input_len = payload_len;

  if (steel_plugin_invoke(&plugin, &call, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "invoke failed: %s\n", err);
    steel_plugin_unload(&plugin);
    free(payload);
    return 5;
  }

  steel_result_free(&result);
  steel_plugin_unload(&plugin);
  free(payload);
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c src/engine_wasmtime_component.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

set +e
"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.component.wasm 4096 8192
rc_small=$?
set -e
if [[ ${rc_small} -eq 0 ]]; then
  echo "expected 8KiB invoke to fail for 4KiB plugin region allotment" >&2
  exit 1
fi

"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.region16k.component.wasm 16384 8192

echo "plugin region allotment requests are enforced and host-policy bounded"
