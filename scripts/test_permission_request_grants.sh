#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"
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
python3 scripts/embed_manifest.py --requested-permissions 0x1 "${wasm_path}" dist/steel-echo-plugin.req-write.component.wasm
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char *resolve_user(void) {
  const char *u = getenv("USER");
  if (u != NULL && u[0] != '\0') {
    return u;
  }
  return "unknown-user";
}

static int load_and_check(const char *path,
                          const steel_permission_rule_t *rules,
                          size_t rule_count,
                          uint32_t expected_granted,
                          uint32_t expected_logger_granted,
                          uint32_t expected_document_granted) {
  steel_plugin_t plugin;
  steel_policy_t policy;
  steel_engine_vtable_t engine;
  char err[256];

  memset(&plugin, 0, sizeof(plugin));
  memset(&policy, 0, sizeof(policy));

  policy.expected_layout_hash = STEEL_EXPECTED_LAYOUT_HASH;
  policy.expected_type_table_hash = STEEL_EXPECTED_TYPE_TABLE_HASH;
  policy.min_abi_minor = 0;
  policy.max_memory_pages = 64;
  policy.permission_rules = rules;
  policy.permission_rule_count = rule_count;
  policy.trusted_attestation_public_key_path = "plugins/echo-plugin/keys/demo_public.pem";
  policy.required_signer_id = "demo-dev";

  engine = steel_wasmtime_component_engine();

  if (steel_plugin_load(&plugin, path, &policy, &engine, err, sizeof(err)) != 0) {
    fprintf(stderr, "plugin load failed: %s\n", err);
    return 1;
  }

  if (plugin.granted_permissions != expected_granted) {
    fprintf(stderr, "granted permissions mismatch: got=0x%x expected=0x%x\n", plugin.granted_permissions,
            expected_granted);
    steel_plugin_unload(&plugin);
    return 2;
  }
  if (plugin.manifest.facet_count < 2 || plugin.facet_granted_permissions == NULL) {
    fprintf(stderr, "facet grant table missing\n");
    steel_plugin_unload(&plugin);
    return 3;
  }
  if (plugin.facet_granted_permissions[0] != expected_logger_granted ||
      plugin.facet_granted_permissions[1] != expected_document_granted) {
    fprintf(stderr,
            "facet granted mismatch: logger=0x%x document=0x%x expected_logger=0x%x expected_document=0x%x\n",
            plugin.facet_granted_permissions[0],
            plugin.facet_granted_permissions[1],
            expected_logger_granted,
            expected_document_granted);
    steel_plugin_unload(&plugin);
    return 4;
  }

  steel_plugin_unload(&plugin);
  return 0;
}

int main(int argc, char **argv) {
  int rc;
  const char *user = resolve_user();
  steel_permission_rule_t deny_rules[] = {
      {"demo-dev", "someone-else", STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK, NULL, 0},
  };
  static const steel_facet_permission_rule_t allow_facet_rules[] = {
      {STEEL_FACET_ID_INIT(0x2a, 0xa2, 0xe8, 0x95, 0x90, 0xbb, 0x47, 0x95, 0x98, 0x42, 0x06, 0x6f, 0x17, 0x4e,
                           0x7f, 0x20),
       0},
      {STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                           0x4f, 0xf0),
       STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK},
  };
  steel_permission_rule_t allow_rules[] = {
      {"demo-dev",
       user,
       STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK,
       allow_facet_rules,
       sizeof(allow_facet_rules) / sizeof(allow_facet_rules[0])},
  };
  if (argc != 2) {
    fprintf(stderr, "usage: %s <plugin.component.wasm>\n", argv[0]);
    return 2;
  }

  rc = load_and_check(argv[1], deny_rules, sizeof(deny_rules) / sizeof(deny_rules[0]), 0, 0, 0);
  if (rc != 0) {
    return rc;
  }

  rc = load_and_check(argv[1],
                      allow_rules,
                      sizeof(allow_rules) / sizeof(allow_rules[0]),
                      STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK,
                      0,
                      STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK);
  if (rc != 0) {
    return rc;
  }

  printf("permission requests are signer+host-user negotiated (deny/allow)\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c src/engine_wasmtime_component.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner" plugins/echo-plugin/dist/steel-echo-plugin.req-write.component.wasm
