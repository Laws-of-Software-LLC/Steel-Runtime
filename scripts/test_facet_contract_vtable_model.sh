#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

cat > "${tmp_dir}/facet_contract.c" <<'SRC'
#include "steel/facet.h"

#include <stddef.h>

static const steel_facet_id_t FACET_TEST =
    STEEL_FACET_ID_INIT(0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb,
                        0xcc, 0xdd);

static const steel_vtable_entry_t TEST_VTABLE[] = {
    {
        .method_id = 1,
        .method_name = "test.echo",
        .steel_fun_signature =
            {
                .param_count = 1,
                .param_types = STEEL_SIG_TYPES(STEEL_SIG_TYPE_BYTES),
                .result_type = STEEL_SIG_TYPE_BYTES,
            },
    },
    {
        .method_id = 2,
        .method_name = "test.ping",
        .steel_fun_signature =
            {
                .param_count = 0,
                .result_type = STEEL_SIG_TYPE_UNIT,
            },
    },
};

_Static_assert(offsetof(steel_vtable_entry_t, steel_fun_signature) > offsetof(steel_vtable_entry_t, method_name),
               "vtable entries must include SteelFunSignature metadata");

static const steel_facet_contract_t TEST_CONTRACT = {
    FACET_TEST,
    TEST_VTABLE,
    2,
};

STEEL_REGISTER_CONTRACT(TEST_CONTRACT);

int steel_test_facet_contract_linked(void) { return 1; }
SRC

cat > "${tmp_dir}/runner.c" <<'SRC'
#include "steel/facet.h"

#include <stdio.h>

int steel_test_facet_contract_linked(void);

int main(void) {
  const steel_facet_id_t facet =
      STEEL_FACET_ID_INIT(0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb,
                          0xcc, 0xdd);
  const steel_vtable_entry_t *entry1;
  const steel_vtable_entry_t *entry2;

  if (steel_test_facet_contract_linked() != 1) {
    fprintf(stderr, "failed to force-link test contract object\n");
    return 1;
  }

  printf("contract_count=%zu\n", steel_contract_count());

  if (steel_contract_count() != 1) {
    fprintf(stderr, "expected one facet contract\n");
    return 2;
  }

  entry1 = steel_contract_find(&facet, 1);
  entry2 = steel_contract_find(&facet, 2);
  if (entry1 == NULL || entry2 == NULL) {
    fprintf(stderr, "expected vtable entries for methods 1 and 2\n");
    return 3;
  }
  if (entry1->method_id != 1 || entry2->method_id != 2) {
    fprintf(stderr, "unexpected method ids in vtable entries\n");
    return 4;
  }
  if (entry1->steel_fun_signature.param_count != 1 || entry1->steel_fun_signature.result_type != STEEL_SIG_TYPE_BYTES) {
    fprintf(stderr, "unexpected typed signature metadata for method 1\n");
    return 5;
  }
  if (entry2->steel_fun_signature.param_count != 0 || entry2->steel_fun_signature.result_type != STEEL_SIG_TYPE_UNIT) {
    fprintf(stderr, "unexpected typed signature metadata for method 2\n");
    return 6;
  }

  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude -c "${tmp_dir}/facet_contract.c" -o "${tmp_dir}/facet_contract.o"
ar rcs "${tmp_dir}/libfacet_contract.a" "${tmp_dir}/facet_contract.o"

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude src/facet_registry.c "${tmp_dir}/runner.c" \
  "${tmp_dir}/libfacet_contract.a" -o "${tmp_dir}/runner"

"${tmp_dir}/runner"
