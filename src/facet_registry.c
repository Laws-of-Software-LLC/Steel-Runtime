#include "steel/facet.h"

#include <stdlib.h>
#include <string.h>

typedef const steel_facet_contract_t *const steel_contract_ptr_t;

/* Keep the section present even in binaries that do not define host contracts. */
static steel_contract_ptr_t g_contract_section_sentinel STEEL_CONTRACT_SECTION_ATTR = NULL;

#if defined(__APPLE__)
extern steel_contract_ptr_t __steel_contracts_start __asm("section$start$__DATA$steel_contracts");
extern steel_contract_ptr_t __steel_contracts_end __asm("section$end$__DATA$steel_contracts");
#else
extern steel_contract_ptr_t __start_steel_contracts[];
extern steel_contract_ptr_t __stop_steel_contracts[];
#endif

static const steel_contract_ptr_t *contract_section_begin(void) {
#if defined(__APPLE__)
  return &__steel_contracts_start;
#else
  return __start_steel_contracts;
#endif
}

static const steel_contract_ptr_t *contract_section_end(void) {
#if defined(__APPLE__)
  return &__steel_contracts_end;
#else
  return __stop_steel_contracts;
#endif
}

static int is_known_signature_type(steel_signature_type_t type) {
  switch (type) {
    case STEEL_SIG_TYPE_VOID:
    case STEEL_SIG_TYPE_BOOL:
    case STEEL_SIG_TYPE_CHAR:
    case STEEL_SIG_TYPE_SCHAR:
    case STEEL_SIG_TYPE_UCHAR:
    case STEEL_SIG_TYPE_SHORT:
    case STEEL_SIG_TYPE_USHORT:
    case STEEL_SIG_TYPE_INT:
    case STEEL_SIG_TYPE_UINT:
    case STEEL_SIG_TYPE_LONG:
    case STEEL_SIG_TYPE_ULONG:
    case STEEL_SIG_TYPE_LLONG:
    case STEEL_SIG_TYPE_ULLONG:
    case STEEL_SIG_TYPE_FLOAT:
    case STEEL_SIG_TYPE_DOUBLE:
    case STEEL_SIG_TYPE_LDOUBLE:
    case STEEL_SIG_TYPE_VOID_PTR:
    case STEEL_SIG_TYPE_OBJ_PTR:
    case STEEL_SIG_TYPE_BYTES:
    case STEEL_SIG_TYPE_U32:
      return 1;
    default:
      return 0;
  }
}

static int validate_contract(const steel_facet_contract_t *contract) {
  size_t i;
  size_t j;

  if (contract == NULL || contract->vtable == NULL || contract->vtable_len == 0) {
    return -1;
  }

  for (i = 0; i < contract->vtable_len; ++i) {
    const steel_vtable_entry_t *entry = &contract->vtable[i];
    if (entry->method_name == NULL) {
      return -1;
    }
    if (steel_signature_validate(&entry->steel_fun_signature) != 0) {
      return -6;
    }
    for (j = i + 1; j < contract->vtable_len; ++j) {
      if (entry->method_id == contract->vtable[j].method_id) {
        return -2;
      }
    }
  }

  return 0;
}

int steel_facet_id_equal(const steel_facet_id_t *lhs, const steel_facet_id_t *rhs) {
  return memcmp(lhs->bytes, rhs->bytes, sizeof(lhs->bytes)) == 0;
}

int steel_contract_register(const steel_facet_contract_t *contract) {
  int rc = validate_contract(contract);
  if (rc != 0) {
    return rc;
  }
  return -4;
}

size_t steel_contract_count(void) {
  const steel_contract_ptr_t *it = contract_section_begin();
  const steel_contract_ptr_t *end = contract_section_end();
  size_t n = 0;

  for (; it < end; ++it) {
    const steel_facet_contract_t *contract = *it;
    if (contract == NULL) {
      continue;
    }
    if (validate_contract(contract) != 0) {
      continue;
    }
    ++n;
  }

  return n;
}

const steel_facet_contract_t *steel_contract_get(size_t idx) {
  const steel_contract_ptr_t *it = contract_section_begin();
  const steel_contract_ptr_t *end = contract_section_end();
  size_t cur = 0;

  for (; it < end; ++it) {
    const steel_facet_contract_t *contract = *it;
    if (contract == NULL) {
      continue;
    }
    if (validate_contract(contract) != 0) {
      continue;
    }
    if (cur == idx) {
      return contract;
    }
    ++cur;
  }

  return NULL;
}

const steel_vtable_entry_t *steel_contract_find(const steel_facet_id_t *facet_id, uint32_t method_id) {
  const steel_contract_ptr_t *it = contract_section_begin();
  const steel_contract_ptr_t *end = contract_section_end();

  if (facet_id == NULL) {
    return NULL;
  }

  for (; it < end; ++it) {
    const steel_facet_contract_t *contract = *it;
    size_t j;
    if (contract == NULL || validate_contract(contract) != 0) {
      continue;
    }
    if (!steel_facet_id_equal(&contract->facet_id, facet_id)) {
      continue;
    }
    for (j = 0; j < contract->vtable_len; ++j) {
      const steel_vtable_entry_t *entry = &contract->vtable[j];
      if (entry->method_id == method_id) {
        return entry;
      }
    }
  }

  return NULL;
}

const steel_vtable_entry_t *steel_contract_find_by_facet_bytes(const uint8_t facet_id_bytes[16], uint32_t method_id) {
  const steel_contract_ptr_t *it = contract_section_begin();
  const steel_contract_ptr_t *end = contract_section_end();

  if (facet_id_bytes == NULL) {
    return NULL;
  }

  for (; it < end; ++it) {
    const steel_facet_contract_t *contract = *it;
    size_t j;
    if (contract == NULL || validate_contract(contract) != 0) {
      continue;
    }
    if (memcmp(contract->facet_id.bytes, facet_id_bytes, 16) != 0) {
      continue;
    }
    for (j = 0; j < contract->vtable_len; ++j) {
      const steel_vtable_entry_t *entry = &contract->vtable[j];
      if (entry->method_id == method_id) {
        return entry;
      }
    }
  }

  return NULL;
}

int steel_signature_equal(const steel_fun_signature_t *lhs, const steel_fun_signature_t *rhs) {
  if (lhs == NULL || rhs == NULL) {
    return 0;
  }
  if (lhs->param_count != rhs->param_count || lhs->result_type != rhs->result_type) {
    return 0;
  }
  if (lhs->param_count == 0) {
    return 1;
  }
  if (lhs->param_types == NULL || rhs->param_types == NULL) {
    return 0;
  }
  return memcmp(lhs->param_types, rhs->param_types, lhs->param_count * sizeof(lhs->param_types[0])) == 0;
}

int steel_signature_validate(const steel_fun_signature_t *signature) {
  size_t i;
  if (signature == NULL) {
    return -1;
  }
  if (signature->param_count > 0 && signature->param_types == NULL) {
    return -1;
  }
  if (!is_known_signature_type(signature->result_type)) {
    return -1;
  }
  for (i = 0; i < signature->param_count; ++i) {
    if (!is_known_signature_type(signature->param_types[i])) {
      return -1;
    }
  }
  return 0;
}

uint64_t steel_signature_type_hash64(const steel_fun_signature_t *signature) {
  uint64_t h = 1469598103934665603ULL;
  size_t i;
  if (signature == NULL || steel_signature_validate(signature) != 0) {
    return 0;
  }
  for (i = 0; i < signature->param_count; ++i) {
    uint16_t t = (uint16_t)signature->param_types[i];
    h ^= (uint64_t)(t & 0xffu);
    h *= 1099511628211ULL;
    h ^= (uint64_t)((t >> 8) & 0xffu);
    h *= 1099511628211ULL;
  }
  {
    uint16_t r = (uint16_t)signature->result_type;
    h ^= (uint64_t)(r & 0xffu);
    h *= 1099511628211ULL;
    h ^= (uint64_t)((r >> 8) & 0xffu);
    h *= 1099511628211ULL;
  }
  return h;
}

uint32_t steel_method_id_hash(const steel_facet_id_t *facet_id,
                              const char *method_name,
                              const steel_fun_signature_t *signature) {
  static const uint8_t domain_sep[] = "steel.method.v1";
  uint32_t h = 2166136261u;
  size_t i;

  if (facet_id == NULL || method_name == NULL || signature == NULL || steel_signature_validate(signature) != 0) {
    return 0;
  }

  for (i = 0; i < sizeof(domain_sep); ++i) {
    h ^= (uint32_t)domain_sep[i];
    h *= 16777619u;
  }
  for (i = 0; i < sizeof(facet_id->bytes); ++i) {
    h ^= (uint32_t)facet_id->bytes[i];
    h *= 16777619u;
  }
  h ^= 0u;
  h *= 16777619u;
  for (i = 0; method_name[i] != '\0'; ++i) {
    h ^= (uint32_t)(uint8_t)method_name[i];
    h *= 16777619u;
  }
  h ^= 0u;
  h *= 16777619u;

  for (i = 0; i < signature->param_count; ++i) {
    uint16_t t = (uint16_t)signature->param_types[i];
    h ^= (uint32_t)(t & 0xffu);
    h *= 16777619u;
    h ^= (uint32_t)((t >> 8) & 0xffu);
    h *= 16777619u;
  }
  {
    uint16_t r = (uint16_t)signature->result_type;
    h ^= (uint32_t)(r & 0xffu);
    h *= 16777619u;
    h ^= (uint32_t)((r >> 8) & 0xffu);
    h *= 16777619u;
  }

  if (h == 0u) {
    return 1u;
  }
  return h;
}

void steel_signature_free(steel_fun_signature_t *signature) {
  if (signature == NULL) {
    return;
  }
  free((void *)signature->param_types);
  signature->param_types = NULL;
  signature->param_count = 0;
  signature->result_type = STEEL_SIG_TYPE_VOID;
}
