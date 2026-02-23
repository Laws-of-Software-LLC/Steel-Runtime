# Steel Runtime Plugin Host (C)

This repository implements a facet-based plugin contract system with zero-trust validation gates for WebAssembly Component plugins.

## What is implemented

- Globally unique facet IDs (`steel_facet_id_t`, 16-byte UUID form).
- Method contracts with full captured signatures and per-method signature hashes.
- Method contracts include explicit typed signatures (`steel_function_signature_t`) in addition to capture strings.
- Method identifiers are deterministic hashes of `(facet_id, method_name, typed_signature)`.
- Link-time registration via linker-section entries (`STEEL_REGISTER_CONTRACT`).
  - New host-defined layouts may be introduced via static linking.
  - Runtime registration is disabled; contract table is immutable after link.
- Pre-load plugin verification from a WASM custom section (`steel.manifest.v1`) with checks for:
  - ABI major/minor version
  - Host layout hash
  - Type-table hash
  - Memory min/max pages (policy constrained)
  - Facet/method existence and signature hash agreement
  - Component hash attestation and manifest signature verification
- Sandbox backend abstraction (`steel_engine_vtable_t`) so plugin execution is isolated from host memory.
  - Plugin outputs are staged in a plugin region and copied into a host-owned result region on invoke.
  - Region lifetimes are explicit (`steel_region_t`) so allocations are torn down with region reset/destroy.
- Typed host invocation helper (`steel_plugin_invoke_typed`) for automatic argument marshalling/unmarshalling.

## Zero-trust model

1. Host reads raw component bytes.
2. Host extracts manifest from custom section `steel.manifest.v1`.
3. Host validates version/hash/layout/memory/contract compatibility.
4. Host computes granted permissions as `requested_permissions & allowed_plugin_permissions` (e.g., optional host-input copy-back writes).
5. Host instantiates sandbox engine only after successful verification.
6. Host invokes methods via canonical byte payloads (no direct host-memory pointer sharing).

## Facet contracts

Contracts are declared in `src/contracts_builtin.c` and registered into a linker section:

- `log.info`
- `document.append`

`signature_hash` values are derived from captured signature strings in the manifest (FNV-1a 64-bit).

## WASM Component Model

WIT world is in `wit/steel-plugin.wit`.

`src/engine_wasmtime_component.c` provides the host execution backend used by `apps/steel_host_main.c`.

## Build

```bash
make
```

Requires OpenSSL development headers/libraries (`libcrypto`) for manifest signature verification.

This builds a host demo executable:

```bash
./build/steel_host path/to/plugin.component.wasm
```

Build and run the echo plugin end-to-end:

```bash
make test-host
```

## CMake Build And Export

Configure and build:

```bash
cmake -S . -B build-cmake -DSTEEL_BUILD_HOST_APP=ON
cmake --build build-cmake -j
```

Install/export package:

```bash
cmake --install build-cmake --prefix /your/prefix
```

Downstream usage:

```cmake
find_package(SteelRuntime REQUIRED)
target_link_libraries(your_target PRIVATE Steel::steel_runtime)
```

## Compile-Time Policy Configuration

Default host policy and permission negotiation settings are configured at compile time in `include/steel/policy_config.h`.
`apps/steel_host_main.c` applies these defaults via `steel_policy_apply_compile_time(&policy)`.

Override them with compiler defines (example):

```bash
make CFLAGS+=' -DSTEEL_POLICY_REQUIRED_SIGNER_ID=\"prod-signer\" -DSTEEL_POLICY_HOST_USER_ID=\"buildbot\" -DSTEEL_POLICY_ALLOWED_PLUGIN_PERMISSIONS=0 '
```

## Manifest layout (`steel.manifest.v1` payload)

Canonical binary wire payload (fixed-width integers use a deterministic byte order):

- Header:
  - `u32 magic` (`STEEL_MANIFEST_MAGIC`)
  - `u16 abi_major`
  - `u16 abi_minor`
  - `u64 host_layout_hash`
  - `u64 type_table_hash`
  - `u32 memory_min_pages`
  - `u32 memory_max_pages`
  - `u32 requested_permissions`
  - `u32 requested_region_bytes` (plugin per-invoke staging-allotment request; `0` means host default)
  - `u32 facet_count`
  - `u32 method_count`
- Facets (`facet_count`):
  - `u8 facet_id[16]`
  - `u32 method_start`
  - `u32 method_count`
  - `u32 requested_permissions` (per-facet permission request; host grants per signer/user policy)
- Methods (`method_count`):
  - `u32 facet_index`
  - `u32 method_id`
  - `u16 signature_len`
  - `u16 reserved`
  - `u64 signature_hash`
  - `u8 signature_capture[signature_len]` (UTF-8, no NUL terminator)
  - Parsed and validated as a typed Steel function signature at load time
- Attestation trailer:
  - `u8 component_sha256[32]` (hash of component bytes excluding manifest section)
  - `u16 signer_id_len`
  - `u8 signer_id[signer_id_len]`
  - `u16 signature_len`
  - `u8 signature[signature_len]` (RSA-SHA256 over manifest payload up to `signer_id`)

## Files

- `include/steel/facet.h`: facet IDs + contract registration API
- `include/steel/plugin_manifest.h`: manifest/policy ABI
- `include/steel/plugin_host.h`: host load/invoke ABI
- `include/steel/region.h`: region allocator/lifetime API
- `src/manifest_verify.c`: WASM custom section parsing + all compatibility checks
- `src/plugin_host.c`: host lifecycle and guarded dispatch
- `src/region.c`: region allocator implementation
- `src/engine_null.c`: no-op backend implementation
- `src/engine_wasmtime_component.c`: component execution backend used by the demo host
- `src/contracts_builtin.c`: sample link-time contract registry
- `apps/steel_host_main.c`: demo host process (separate from framework library)
