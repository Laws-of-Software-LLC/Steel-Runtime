#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cat > "${tmp_dir}/static_contract.c" <<'SRC'
#include "steel/facet.h"

static const steel_facet_id_t FACET_STATIC =
    STEEL_FACET_ID_INIT(0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
                        0xba, 0xbe);

static const steel_vtable_entry_t STATIC_VTABLE[] = {
    {
        .method_id = 7,
        .method_name = "static.layout.added",
        .steel_fun_signature =
            {
                .param_count = 1,
                .param_types = STEEL_SIG_TYPES(STEEL_SIG_TYPE_BYTES),
                .result_type = STEEL_SIG_TYPE_BYTES,
            },
    },
};

static const steel_facet_contract_t CONTRACT_STATIC = {
    FACET_STATIC,
    STATIC_VTABLE,
    1,
};

STEEL_REGISTER_CONTRACT(CONTRACT_STATIC);

int steel_test_static_contract_linked(void) { return 1; }
SRC

cat > "${tmp_dir}/runner.c" <<'SRC'
#include "steel/facet.h"

#include <stdio.h>

int steel_test_static_contract_linked(void);

int main(void) {
  const steel_facet_id_t facet_static =
      STEEL_FACET_ID_INIT(0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
                          0xba, 0xbe);
  const steel_vtable_entry_t *entry;

  if (steel_test_static_contract_linked() != 1) {
    fprintf(stderr, "failed to force-link static contract object\n");
    return 1;
  }

  printf("contract_count=%zu\n", steel_contract_count());

  if (steel_contract_count() != 1) {
    fprintf(stderr, "expected contract_count=1 after static link-time registration\n");
    return 2;
  }

  entry = steel_contract_find(&facet_static, 7);
  if (entry == NULL) {
    fprintf(stderr, "expected static facet/method to resolve\n");
    return 3;
  }

  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude -c "${tmp_dir}/static_contract.c" -o "${tmp_dir}/static_contract.o"
ar rcs "${tmp_dir}/libstatic_contract.a" "${tmp_dir}/static_contract.o"

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude src/facet_registry.c "${tmp_dir}/runner.c" \
  "${tmp_dir}/libstatic_contract.a" -o "${tmp_dir}/runner"

"${tmp_dir}/runner"
