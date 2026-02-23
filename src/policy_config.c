#include "steel/policy_config.h"

#include <string.h>

void steel_policy_apply_compile_time(steel_policy_t *policy) {
  static const steel_permission_rule_t permission_rules[] = {
      {
          .signer_id = STEEL_POLICY_REQUIRED_SIGNER_ID,
          .host_user_id = STEEL_POLICY_HOST_USER_ID,
          .allowed_permissions = STEEL_POLICY_ALLOWED_PLUGIN_PERMISSIONS,
          .facet_permissions = NULL,
          .facet_permission_count = 0,
      },
  };

  if (policy == NULL) {
    return;
  }

  memset(policy, 0, sizeof(*policy));
  policy->host_user_id = STEEL_POLICY_HOST_USER_ID;
  policy->expected_layout_hash = STEEL_POLICY_EXPECTED_LAYOUT_HASH;
  policy->expected_type_table_hash = STEEL_POLICY_EXPECTED_TYPE_TABLE_HASH;
  policy->min_abi_minor = STEEL_POLICY_MIN_ABI_MINOR;
  policy->max_memory_pages = STEEL_POLICY_MAX_MEMORY_PAGES;
  policy->default_plugin_region_bytes = STEEL_POLICY_DEFAULT_PLUGIN_REGION_BYTES;
  policy->max_plugin_region_bytes = STEEL_POLICY_MAX_PLUGIN_REGION_BYTES;
  policy->allowed_plugin_permissions = STEEL_POLICY_ALLOWED_PLUGIN_PERMISSIONS;
  policy->trusted_attestation_public_key_path = STEEL_POLICY_TRUSTED_ATTESTATION_PUBLIC_KEY_PATH;
  policy->required_signer_id = STEEL_POLICY_REQUIRED_SIGNER_ID;
#if STEEL_POLICY_USE_PERMISSION_RULES
  policy->permission_rules = permission_rules;
  policy->permission_rule_count = sizeof(permission_rules) / sizeof(permission_rules[0]);
#endif
}
