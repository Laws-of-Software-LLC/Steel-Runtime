#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cat > "${tmp_dir}/sig_types_unbounded.c" <<'SRC'
#include "steel/facet.h"

#include <stdio.h>

static const steel_facet_id_t FACET_SIG_C_TYPES =
    STEEL_FACET_ID_INIT(0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                        0xf0, 0x01);

static const steel_signature_type_t ALL_C_TYPES[] = {
    STEEL_SIG_TYPE_BOOL,    STEEL_SIG_TYPE_CHAR,    STEEL_SIG_TYPE_SCHAR,  STEEL_SIG_TYPE_UCHAR,
    STEEL_SIG_TYPE_SHORT,   STEEL_SIG_TYPE_USHORT,  STEEL_SIG_TYPE_INT,    STEEL_SIG_TYPE_UINT,
    STEEL_SIG_TYPE_LONG,    STEEL_SIG_TYPE_ULONG,   STEEL_SIG_TYPE_LLONG,  STEEL_SIG_TYPE_ULLONG,
    STEEL_SIG_TYPE_FLOAT,   STEEL_SIG_TYPE_DOUBLE,  STEEL_SIG_TYPE_LDOUBLE,
    STEEL_SIG_TYPE_VOID_PTR, STEEL_SIG_TYPE_OBJ_PTR,
};

static const steel_vtable_entry_t VTABLE[] = {
    {
        .method_id = 1,
        .method_name = "typed.c.types",
        .steel_fun_signature =
            {
                .param_count = sizeof(ALL_C_TYPES) / sizeof(ALL_C_TYPES[0]),
                .param_types = ALL_C_TYPES,
                .result_type = STEEL_SIG_TYPE_VOID,
            },
    },
    {
        .method_id = 2,
        .method_name = "typed.unbounded.params",
        .steel_fun_signature =
            {
                .param_count = 12,
                .param_types = STEEL_SIG_TYPES(
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT,
                    STEEL_SIG_TYPE_INT),
                .result_type = STEEL_SIG_TYPE_INT,
            },
    },
};

static const steel_facet_contract_t CONTRACT = {
    FACET_SIG_C_TYPES,
    VTABLE,
    2,
};

STEEL_REGISTER_CONTRACT(CONTRACT);

int steel_test_sig_types_contract_linked(void) { return 1; }

int main(void) {
  const steel_vtable_entry_t *entry;

  if (steel_test_sig_types_contract_linked() != 1) {
    fprintf(stderr, "failed to force-link signature contract object\n");
    return 1;
  }

  entry = steel_contract_find(&FACET_SIG_C_TYPES, 2);
  if (entry == NULL) {
    fprintf(stderr, "method lookup failed\n");
    return 1;
  }
  if (entry->steel_fun_signature.param_count != 12) {
    fprintf(stderr, "expected unbounded param count support\n");
    return 1;
  }
  if (entry->steel_fun_signature.result_type != STEEL_SIG_TYPE_INT) {
    fprintf(stderr, "unexpected result type\n");
    return 1;
  }

  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude src/facet_registry.c "${tmp_dir}/sig_types_unbounded.c" -o "${tmp_dir}/runner"
"${tmp_dir}/runner"

echo "C type signatures + unbounded params enforced"
