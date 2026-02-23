#include "steel/facet.h"

/* Example globally-unique facet IDs. Generate new UUIDs for production facets. */
static const steel_facet_id_t FACET_LOGGER =
    STEEL_FACET_ID_INIT(0x2a, 0xa2, 0xe8, 0x95, 0x90, 0xbb, 0x47, 0x95, 0x98, 0x42, 0x06, 0x6f, 0x17, 0x4e,
                        0x7f, 0x20);

static const steel_facet_id_t FACET_DOCUMENT =
    STEEL_FACET_ID_INIT(0x94, 0x65, 0xfa, 0x66, 0xde, 0xe4, 0x49, 0x42, 0xab, 0x33, 0xa0, 0xf5, 0x95, 0x99,
                        0x4f, 0xf0);

/* steel_method_id_hash(FACET_LOGGER, "log.info", [BYTES] -> VOID) */
static const uint32_t METHOD_ID_LOG_INFO = 0xd399d6dfu;
/* steel_method_id_hash(FACET_DOCUMENT, "document.append", [U32, BYTES] -> BYTES) */
static const uint32_t METHOD_ID_DOCUMENT_APPEND = 0x26b9023eu;

static const steel_vtable_entry_t LOGGER_VTABLE[] = {
    {
        .method_id = METHOD_ID_LOG_INFO,
        .method_name = "log.info",
        .steel_fun_signature =
            {
                .param_count = 1,
                .param_types = STEEL_SIG_TYPES(STEEL_SIG_TYPE_BYTES),
                .result_type = STEEL_SIG_TYPE_VOID,
            },
    },
};

static const steel_vtable_entry_t DOCUMENT_VTABLE[] = {
    {
        .method_id = METHOD_ID_DOCUMENT_APPEND,
        .method_name = "document.append",
        .steel_fun_signature =
            {
                .param_count = 2,
                .param_types = STEEL_SIG_TYPES(STEEL_SIG_TYPE_U32, STEEL_SIG_TYPE_BYTES),
                .result_type = STEEL_SIG_TYPE_BYTES,
            },
    },
};

static const steel_facet_contract_t CONTRACT_LOGGER = {
    FACET_LOGGER,
    LOGGER_VTABLE,
    1,
};

static const steel_facet_contract_t CONTRACT_DOCUMENT = {
    FACET_DOCUMENT,
    DOCUMENT_VTABLE,
    1,
};

STEEL_REGISTER_CONTRACT(CONTRACT_LOGGER)
STEEL_REGISTER_CONTRACT(CONTRACT_DOCUMENT)

int steel_builtin_contracts_linked(void) { return 1; }
