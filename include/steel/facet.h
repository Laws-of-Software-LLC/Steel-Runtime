#ifndef STEEL_FACET_H
#define STEEL_FACET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct steel_facet_id {
  uint8_t bytes[16];
} steel_facet_id_t;

typedef enum steel_signature_type {
  STEEL_SIG_TYPE_VOID = 0,
  STEEL_SIG_TYPE_BOOL = 1,
  STEEL_SIG_TYPE_CHAR = 2,
  STEEL_SIG_TYPE_SCHAR = 3,
  STEEL_SIG_TYPE_UCHAR = 4,
  STEEL_SIG_TYPE_SHORT = 5,
  STEEL_SIG_TYPE_USHORT = 6,
  STEEL_SIG_TYPE_INT = 7,
  STEEL_SIG_TYPE_UINT = 8,
  STEEL_SIG_TYPE_LONG = 9,
  STEEL_SIG_TYPE_ULONG = 10,
  STEEL_SIG_TYPE_LLONG = 11,
  STEEL_SIG_TYPE_ULLONG = 12,
  STEEL_SIG_TYPE_FLOAT = 13,
  STEEL_SIG_TYPE_DOUBLE = 14,
  STEEL_SIG_TYPE_LDOUBLE = 15,
  STEEL_SIG_TYPE_VOID_PTR = 16,
  STEEL_SIG_TYPE_OBJ_PTR = 17,
  /* Legacy aliases retained for backward compatibility with existing manifests. */
  STEEL_SIG_TYPE_BYTES = 100,
  STEEL_SIG_TYPE_U32 = 101,
  STEEL_SIG_TYPE_UNIT = STEEL_SIG_TYPE_VOID,
} steel_signature_type_t;

#define STEEL_SIG_TYPES(...) ((const steel_signature_type_t[]){__VA_ARGS__})

typedef struct steel_fun_signature {
  size_t param_count;
  const steel_signature_type_t *param_types;
  steel_signature_type_t result_type;
} steel_fun_signature_t;

typedef struct steel_vtable_entry {
  uint32_t method_id;
  const char *method_name;
  steel_fun_signature_t steel_fun_signature;
} steel_vtable_entry_t;

typedef struct steel_facet_contract {
  steel_facet_id_t facet_id;
  const steel_vtable_entry_t *vtable;
  size_t vtable_len;
} steel_facet_contract_t;

int steel_facet_id_equal(const steel_facet_id_t *lhs, const steel_facet_id_t *rhs);

int steel_contract_register(const steel_facet_contract_t *contract);
size_t steel_contract_count(void);
const steel_facet_contract_t *steel_contract_get(size_t idx);
const steel_vtable_entry_t *steel_contract_find(const steel_facet_id_t *facet_id, uint32_t method_id);
const steel_vtable_entry_t *steel_contract_find_by_facet_bytes(const uint8_t facet_id_bytes[16], uint32_t method_id);
int steel_signature_equal(const steel_fun_signature_t *lhs, const steel_fun_signature_t *rhs);
int steel_signature_validate(const steel_fun_signature_t *signature);
uint64_t steel_signature_type_hash64(const steel_fun_signature_t *signature);
uint32_t steel_method_id_hash(const steel_facet_id_t *facet_id,
                              const char *method_name,
                              const steel_fun_signature_t *signature);
void steel_signature_free(steel_fun_signature_t *signature);

#define STEEL_FACET_ID_INIT(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15) \
  {{(uint8_t)(b0), (uint8_t)(b1), (uint8_t)(b2), (uint8_t)(b3), (uint8_t)(b4), (uint8_t)(b5),        \
    (uint8_t)(b6), (uint8_t)(b7), (uint8_t)(b8), (uint8_t)(b9), (uint8_t)(b10), (uint8_t)(b11),      \
    (uint8_t)(b12), (uint8_t)(b13), (uint8_t)(b14), (uint8_t)(b15)}}

#if defined(__APPLE__)
#define STEEL_CONTRACT_SECTION_ATTR __attribute__((used, section("__DATA,steel_contracts")))
#else
#define STEEL_CONTRACT_SECTION_ATTR __attribute__((used, section("steel_contracts")))
#endif

#define STEEL_REGISTER_CONTRACT(contract_symbol)                                                  \
  static const steel_facet_contract_t *const steel_contract_ref_##contract_symbol                 \
      STEEL_CONTRACT_SECTION_ATTR = &(contract_symbol);

#ifdef __cplusplus
}
#endif

#endif
