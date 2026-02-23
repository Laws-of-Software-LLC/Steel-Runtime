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

static int malicious_invoke(steel_plugin_t *plugin,
                            const steel_call_t *call,
                            steel_result_t *result,
                            char *err,
                            size_t err_len) {
  size_t i;
  (void)plugin;
  (void)err;
  (void)err_len;

  for (i = 0; i < call->input_len; ++i) {
    call->input[i] = '!';
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
  uint8_t critical_memory[] = "CRITICAL_HOST_MEMORY_DO_NOT_TOUCH";
  uint8_t critical_before[sizeof(critical_memory)];
  size_t i;

  memset(&plugin, 0, sizeof(plugin));
  memset(&call, 0, sizeof(call));
  memset(&result, 0, sizeof(result));

  memcpy(critical_before, critical_memory, sizeof(critical_memory));

  steel_region_init(&plugin.plugin_region, STEEL_DEFAULT_PLUGIN_REGION_BYTES);
  plugin.plugin_region_allotment_bytes = STEEL_DEFAULT_PLUGIN_REGION_BYTES;
  plugin.engine.invoke = malicious_invoke;

  call.facet_id = FACET_DOCUMENT;
  call.method_id = METHOD_ID_DOCUMENT_APPEND;
  call.receiver_handle = 1;
  call.permissions = 0;
  call.input = critical_memory;
  call.input_len = sizeof(critical_memory) - 1;

  if (steel_plugin_invoke(&plugin, &call, &result, err, sizeof(err)) != 0) {
    fprintf(stderr, "invoke failed: %s\n", err);
    steel_region_destroy(&plugin.plugin_region);
    return 1;
  }

  if (memcmp(critical_memory, critical_before, sizeof(critical_memory)) != 0) {
    fprintf(stderr, "critical host memory was modified without permission\n");
    steel_result_free(&result);
    steel_region_destroy(&plugin.plugin_region);
    return 2;
  }

  for (i = 0; i < result.output_len; ++i) {
    if (result.output[i] != '!') {
      fprintf(stderr, "malicious mutation did not occur in plugin region output\n");
      steel_result_free(&result);
      steel_region_destroy(&plugin.plugin_region);
      return 3;
    }
  }

  steel_result_free(&result);
  steel_region_destroy(&plugin.plugin_region);
  printf("malicious plugin could not modify critical host memory without permission\n");
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 ${openssl_cflags} -Iinclude \
  src/facet_registry.c src/sha256.c src/region.c src/manifest_verify.c src/plugin_host.c \
  "${tmp_dir}/runner.c" build/libsteel_contracts_builtin.a -o "${tmp_dir}/runner" ${openssl_libs}

"${tmp_dir}/runner"
