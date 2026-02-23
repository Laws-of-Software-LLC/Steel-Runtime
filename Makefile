CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lcrypto
endif
CFLAGS += $(OPENSSL_CFLAGS)
GEN_DIR := build/generated
GEN_PROXY_HDR := $(GEN_DIR)/include/steel/proxy_generated.h
GEN_PROXY_SRC := $(GEN_DIR)/src/proxy_generated.c
GEN_PROXY_OBJ := build/proxy_generated.o
ABI_HASH_HDR := include/steel/abi_hashes.h
ABI_HASH_PY := plugins/echo-plugin/scripts/abi_hashes_generated.py
INCLUDES := -Iinclude -I$(GEN_DIR)/include
STEEL_SRC := \
  src/policy_config.c \
  src/facet_registry.c \
  src/sha256.c \
  src/region.c \
  src/registry.c \
  src/manifest_verify.c \
  src/plugin_host.c \
  src/proxy.c \
  src/engine_null.c \
  src/engine_wasmtime_component.c
APP_SRC := apps/steel_host_main.c

ifeq ($(STEEL_ENABLE_WASMTIME),1)
CFLAGS += -DSTEEL_ENABLE_WASMTIME
endif

STEEL_OBJ := $(patsubst src/%.c,build/%.o,$(STEEL_SRC))
STEEL_OBJ += $(GEN_PROXY_OBJ)
APP_OBJ := $(patsubst apps/%.c,build/%.o,$(APP_SRC))
CONTRACTS_OBJ := build/contracts_builtin.o
CONTRACTS_LIB := build/libsteel_contracts_builtin.a
STEEL_LIB := build/libsteel_runtime.a
BIN := build/steel_host

.PHONY: all clean generate-proxies generate-abi-hashes test test-plugin test-host test-security test-static test-memory test-perms test-malicious test-requests test-attest test-critical test-vtable test-typed-sig test-plugin-fallback test-sig-types test-region-allotment test-typed-invoke test-proxy test-registry plugin steel-lib

all: generate-abi-hashes steel-lib $(BIN)

generate-proxies: $(GEN_PROXY_HDR) $(GEN_PROXY_SRC)
generate-abi-hashes: $(ABI_HASH_HDR) $(ABI_HASH_PY)
steel-lib: $(STEEL_LIB)

plugin:
	cd plugins/echo-plugin && ./scripts/build_component.sh

test-plugin:
	cd plugins/echo-plugin && cargo test

test-host:
	./scripts/test_host_echo.sh

test-plugin-fallback:
	./scripts/test_plugin_build_fallback.sh

test-security:
	./scripts/test_dynamic_contract_reject.sh

test-static:
	./scripts/test_static_contract_accept.sh

test-memory:
	./scripts/test_memory_isolation_regions.sh

test-perms:
	./scripts/test_host_memory_write_permission.sh

test-malicious:
	./scripts/test_malicious_plugin_cannot_modify_critical.sh

test-requests:
	./scripts/test_permission_request_grants.sh

test-attest:
	./scripts/test_attestation_signature_reject.sh

test-critical:
	./scripts/test_critical_memory_writeback_forbidden.sh

test-vtable:
	./scripts/test_facet_contract_vtable_model.sh

test-typed-sig:
	./scripts/test_typed_signature_contract_enforced.sh

test-sig-types:
	./scripts/test_signature_c_types_unbounded_params.sh

test-region-allotment:
	./scripts/test_plugin_region_allotment.sh

test-typed-invoke:
	./scripts/test_typed_invoke_auto_marshal.sh

test-proxy:
	./scripts/test_proxy_api.sh

test-registry:
	bash ./scripts/test_registry_enumeration.sh

test: test-plugin test-host test-plugin-fallback test-security test-static test-memory test-perms test-malicious test-requests test-attest test-critical test-vtable test-typed-sig test-sig-types test-region-allotment test-typed-invoke test-proxy test-registry

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/%.o: apps/%.c | build
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(ABI_HASH_HDR) $(ABI_HASH_PY): scripts/generate_abi_hashes.py include/steel/facet.h
	python3 scripts/generate_abi_hashes.py --facet-header include/steel/facet.h --c-out $(ABI_HASH_HDR) --py-out $(ABI_HASH_PY)

$(GEN_PROXY_HDR) $(GEN_PROXY_SRC): scripts/generate_proxies.py src/contracts_builtin.c | build
	python3 scripts/generate_proxies.py --input src/contracts_builtin.c --header $(GEN_PROXY_HDR) --source $(GEN_PROXY_SRC)

$(GEN_PROXY_OBJ): $(GEN_PROXY_SRC) $(GEN_PROXY_HDR) | build
	$(CC) $(CFLAGS) $(INCLUDES) -c $(GEN_PROXY_SRC) -o $(GEN_PROXY_OBJ)

build/steel_host_main.o: $(GEN_PROXY_HDR) $(ABI_HASH_HDR)

$(STEEL_LIB): $(STEEL_OBJ)
	ar rcs $@ $(STEEL_OBJ)

$(BIN): $(APP_OBJ) $(STEEL_LIB) $(CONTRACTS_LIB)
	$(CC) $(CFLAGS) $(APP_OBJ) $(STEEL_LIB) $(CONTRACTS_LIB) -o $@ $(OPENSSL_LIBS)

$(CONTRACTS_LIB): $(CONTRACTS_OBJ)
	ar rcs $@ $<

$(CONTRACTS_OBJ): | build

clean:
	rm -rf build
