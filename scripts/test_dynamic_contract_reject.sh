#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

uname_s="$(uname -s)"
lib_ext="so"
dlopen_flags=""
export_dynamic_flag="-rdynamic"
if [[ "${uname_s}" == "Darwin" ]]; then
  lib_ext="dylib"
  dlopen_flags="-undefined dynamic_lookup"
  export_dynamic_flag="-Wl,-export_dynamic"
fi

cat > "${tmp_dir}/bad_contract.c" <<'SRC'
#include "steel/facet.h"

static const steel_facet_id_t FACET_BAD =
    STEEL_FACET_ID_INIT(0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                        0xbe, 0xef);

static const steel_vtable_entry_t BAD_VTABLE[] = {
    {
        .method_id = 1,
        .method_name = "bad.from.dynamic",
        .steel_fun_signature =
            {
                .param_count = 1,
                .param_types = STEEL_SIG_TYPES(STEEL_SIG_TYPE_BYTES),
                .result_type = STEEL_SIG_TYPE_BYTES,
            },
    },
};

static const steel_facet_contract_t CONTRACT_BAD = {
    FACET_BAD,
    BAD_VTABLE,
    1,
};

static int g_register_rc = 999;

__attribute__((constructor)) static void load_ctor(void) { g_register_rc = steel_contract_register(&CONTRACT_BAD); }

int steel_test_shared_register_result(void) { return g_register_rc; }
SRC

cat > "${tmp_dir}/runner.c" <<'SRC'
#include "steel/facet.h"

#include <dlfcn.h>
#include <stdio.h>

typedef int (*get_rc_fn_t)(void);

int main(int argc, char **argv) {
  void *h;
  get_rc_fn_t get_rc;
  int rc;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <lib>\n", argv[0]);
    return 2;
  }

  h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (h == NULL) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 3;
  }

  get_rc = (get_rc_fn_t)dlsym(h, "steel_test_shared_register_result");
  if (get_rc == NULL) {
    fprintf(stderr, "dlsym failed: %s\n", dlerror());
    dlclose(h);
    return 4;
  }

  rc = get_rc();
  printf("register_rc=%d\n", rc);
  printf("contract_count=%zu\n", steel_contract_count());

  dlclose(h);

  if (rc != -4) {
    fprintf(stderr, "expected register_rc=-4 for runtime registration rejection\n");
    return 5;
  }
  if (steel_contract_count() != 0) {
    fprintf(stderr, "expected no contracts registered from dynamic library\n");
    return 6;
  }

  return 0;
}
SRC

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude src/facet_registry.c "${tmp_dir}/runner.c" \
  -o "${tmp_dir}/runner" ${export_dynamic_flag}

cc -std=c11 -Wall -Wextra -Werror -O2 -Iinclude "${tmp_dir}/bad_contract.c" \
  -o "${tmp_dir}/libbad.${lib_ext}" -shared -fPIC ${dlopen_flags}

"${tmp_dir}/runner" "${tmp_dir}/libbad.${lib_ext}"
