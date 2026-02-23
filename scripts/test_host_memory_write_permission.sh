#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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

#include <stdio.h>
#include <string.h>

static const steel_facet_id_t FACET_DOCUMENT =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                        0x4f, 0xf0);
static const uint32_t METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;
static const uint8_t *g_expected_host_input_ptr = NULL;
static int g_received_direct_host_ptr = 0;

static int mutating_invoke(steel_plugin_t *plugin,
                           const steel_call_t *call,
                           steel_result_t *result,
                           char *err,
                           size_t err_len) {
  if (g_expected_host_input_ptr != NULL && call->input == g_expected_host_input_ptr) {
    g_received_direct_host_ptr = 1;
  }
  (void)plugin;
  (void)err;
  (void)err_len;
  if (call->input_len > 0 && call->input != NULL) {
    call->input[0] = 'Z';
  }
  result->output = call->input;
  result->output_len = call->input_len;
  return 0;
}

int main(void) {
  steel_plugin_t plugin;
  steel_call_t call;
  steel_result_t result;
  char err[128];
  uint8_t input_no_perm[] = "hello";
  uint8_t input_with_perm[] = "hello";

  memset(&plugin, 0, sizeof(plugin));
  memset(&call, 0, sizeof(call));
  memset(&result, 0, sizeof(result));

  steel_region_init(&plugin.plugin_region, STEEL_DEFAULT_PLUGIN_REGION_BYTES);
  plugin.plugin_region_allotment_bytes = STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  plugin.engine.invoke = mutating_invoke;
  plugin.granted_permissions = STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK;

  call.facet_id = FACET_DOCUMENT;
  call.method_id = METHOD_ID_DOCUMENT_APPEND;
  call.receiver_handle = 1;

  call.permissions = 0;
  g_expected_host_input_ptr = input_no_perm;
  call.input = input_no_perm;
  call.input_len = sizeof(input_no_perm) - 1;

  if (steel_plugin_invoke(&plugin, &call, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "invoke (no permission) failed: %s\n", err);
    return 1;
  }
  if (input_no_perm[0] != 'h') {
    fprintf(stderr, "host memory modified without permission\n");
    return 2;
  }
  steel_result_free(&result);

  memset(&result, 0, sizeof(result));
  call.permissions = STEEL_CALL_PERM_ALLOW_HOST_INPUT_COPYBACK;
  g_expected_host_input_ptr = input_with_perm;
  call.input = input_with_perm;
  call.input_len = sizeof(input_with_perm) - 1;

  if (steel_plugin_invoke(&plugin, &call, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "invoke (with permission) failed: %s\n", err);
    return 3;
  }
  if (call.input == result.output) {
    fprintf(stderr, "plugin output unexpectedly aliases host input pointer\n");
    return 4;
  }
  if (input_with_perm[0] != 'Z') {
    fprintf(stderr, "host memory not modified with explicit permission\n");
    return 5;
  }
  if (g_received_direct_host_ptr) {
    fprintf(stderr, "plugin received direct host input pointer\n");
    return 6;
  }
  steel_result_free(&result);

  steel_region_destroy(&plugin.plugin_region);
  printf("host write permission gate passed\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner"
