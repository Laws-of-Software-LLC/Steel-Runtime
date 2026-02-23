#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cat > "${tmp_dir}/typed_sig_contract.c" <<'SRC'
#include "steel/facet.h"

static const steel_facet_id_t FACET_SIG_MISMATCH =
    STEEL_FACET_ID_INIT(0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22,
                        0x33, 0x44);

static const steel_vtable_entry_t BAD_SIG_VTABLE[] = {
    {
        .method_id = 1,
        .method_name = "typed.sig.mismatch",
        .steel_fun_signature =
            {
                .param_count = 1,
                .param_types = NULL,
                .result_type = STEEL_SIG_TYPE_BYTES,
            },
    },
};

static const steel_facet_contract_t CONTRACT_SIG_MISMATCH = {
    FACET_SIG_MISMATCH,
    BAD_SIG_VTABLE,
    1,
};

int main(void) {
  int rc = steel_contract_register(&CONTRACT_SIG_MISMATCH);
  if (rc != -6) {
    return 1;
  }
  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude src/facet_registry.c "${tmp_dir}/typed_sig_contract.c" -o "${tmp_dir}/runner"
"${tmp_dir}/runner"
