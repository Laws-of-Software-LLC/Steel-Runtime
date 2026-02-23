cmake_minimum_required(VERSION 3.20)

project(SteelRuntime VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(STEEL_ENABLE_WASMTIME "Enable Wasmtime backend compile flag" OFF)
option(STEEL_BUILD_HOST_APP "Build demo steel_host executable" ON)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(OpenSSL REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(STEEL_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(STEEL_GEN_INCLUDE_DIR "${STEEL_GEN_DIR}/include")
set(STEEL_GEN_SRC_DIR "${STEEL_GEN_DIR}/src")

set(STEEL_ABI_HASH_HDR "${STEEL_GEN_INCLUDE_DIR}/steel/abi_hashes.h")
set(STEEL_ABI_HASH_PY "${STEEL_GEN_DIR}/abi_hashes_generated.py")
set(STEEL_PROXY_GEN_HDR "${STEEL_GEN_INCLUDE_DIR}/steel/proxy_generated.h")
set(STEEL_PROXY_GEN_SRC "${STEEL_GEN_SRC_DIR}/proxy_generated.c")

add_custom_command(
  OUTPUT "${STEEL_ABI_HASH_HDR}" "${STEEL_ABI_HASH_PY}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${STEEL_GEN_INCLUDE_DIR}/steel"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_abi_hashes.py"
          --facet-header "${CMAKE_CURRENT_SOURCE_DIR}/include/steel/facet.h"
          --c-out "${STEEL_ABI_HASH_HDR}"
          --py-out "${STEEL_ABI_HASH_PY}"
  DEPENDS
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_abi_hashes.py"
          "${CMAKE_CURRENT_SOURCE_DIR}/include/steel/facet.h"
  VERBATIM
)

add_custom_target(steel_generate_abi_hashes
  DEPENDS "${STEEL_ABI_HASH_HDR}" "${STEEL_ABI_HASH_PY}"
)

add_custom_command(
  OUTPUT "${STEEL_PROXY_GEN_HDR}" "${STEEL_PROXY_GEN_SRC}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${STEEL_GEN_INCLUDE_DIR}/steel"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${STEEL_GEN_SRC_DIR}"
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_proxies.py"
          --input "${CMAKE_CURRENT_SOURCE_DIR}/src/contracts_builtin.c"
          --header "${STEEL_PROXY_GEN_HDR}"
          --source "${STEEL_PROXY_GEN_SRC}"
  DEPENDS
          "${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_proxies.py"
          "${CMAKE_CURRENT_SOURCE_DIR}/src/contracts_builtin.c"
  VERBATIM
)

add_custom_target(steel_generate_proxies
  DEPENDS "${STEEL_PROXY_GEN_HDR}" "${STEEL_PROXY_GEN_SRC}"
)

add_library(steel_contracts_builtin STATIC
  src/contracts_builtin.c
)
add_library(Steel::steel_contracts_builtin ALIAS steel_contracts_builtin)

target_include_directories(steel_contracts_builtin
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

add_library(steel_runtime STATIC
  src/policy_config.c
  src/facet_registry.c
  src/sha256.c
  src/region.c
  src/registry.c
  src/manifest_verify.c
  src/plugin_host.c
  src/proxy.c
  src/engine_null.c
  src/engine_wasmtime_component.c
  "${STEEL_PROXY_GEN_SRC}"
)
add_library(Steel::steel_runtime ALIAS steel_runtime)

add_dependencies(steel_runtime steel_generate_abi_hashes steel_generate_proxies)

target_include_directories(steel_runtime
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${STEEL_GEN_INCLUDE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(steel_runtime
  PUBLIC
    OpenSSL::Crypto
    steel_contracts_builtin
)

if(STEEL_ENABLE_WASMTIME)
  target_compile_definitions(steel_runtime PUBLIC STEEL_ENABLE_WASMTIME)
endif()

if(STEEL_BUILD_HOST_APP)
  add_executable(steel_host apps/steel_host_main.c)
  add_dependencies(steel_host steel_generate_abi_hashes steel_generate_proxies)
  target_link_libraries(steel_host PRIVATE steel_runtime)
  target_include_directories(steel_host PRIVATE "${STEEL_GEN_INCLUDE_DIR}")
  install(TARGETS steel_host RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

if(BUILD_TESTING)
  find_program(BASH_PROGRAM bash REQUIRED)

  function(steel_add_script_test test_name script_name)
    add_test(
      NAME "${test_name}"
      COMMAND "${BASH_PROGRAM}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/${script_name}"
    )
    set_tests_properties(
      "${test_name}"
      PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        RUN_SERIAL TRUE
    )
  endfunction()

  add_test(
    NAME steel_plugin_cargo_test
    COMMAND cargo test
  )
  set_tests_properties(
    steel_plugin_cargo_test
    PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/plugins/echo-plugin"
      RUN_SERIAL TRUE
      LABELS "build;integration"
  )

  steel_add_script_test(steel_test_host_echo test_host_echo.sh)
  set_tests_properties(steel_test_host_echo PROPERTIES LABELS "fast;integration")
  steel_add_script_test(steel_test_plugin_build_fallback test_plugin_build_fallback.sh)
  set_tests_properties(steel_test_plugin_build_fallback PROPERTIES LABELS "build;integration")
  steel_add_script_test(steel_test_dynamic_contract_reject test_dynamic_contract_reject.sh)
  set_tests_properties(steel_test_dynamic_contract_reject PROPERTIES LABELS "security;policy;integration")
  steel_add_script_test(steel_test_static_contract_accept test_static_contract_accept.sh)
  set_tests_properties(steel_test_static_contract_accept PROPERTIES LABELS "policy;integration")
  steel_add_script_test(steel_test_memory_isolation_regions test_memory_isolation_regions.sh)
  set_tests_properties(steel_test_memory_isolation_regions PROPERTIES LABELS "security;integration")
  steel_add_script_test(steel_test_host_memory_write_permission test_host_memory_write_permission.sh)
  set_tests_properties(steel_test_host_memory_write_permission PROPERTIES LABELS "security;policy;integration")
  steel_add_script_test(steel_test_malicious_plugin_cannot_modify_critical test_malicious_plugin_cannot_modify_critical.sh)
  set_tests_properties(steel_test_malicious_plugin_cannot_modify_critical PROPERTIES LABELS "security;integration")
  steel_add_script_test(steel_test_permission_request_grants test_permission_request_grants.sh)
  set_tests_properties(steel_test_permission_request_grants PROPERTIES LABELS "policy;integration")
  steel_add_script_test(steel_test_attestation_signature_reject test_attestation_signature_reject.sh)
  set_tests_properties(steel_test_attestation_signature_reject PROPERTIES LABELS "security;integration")
  steel_add_script_test(steel_test_critical_memory_writeback_forbidden test_critical_memory_writeback_forbidden.sh)
  set_tests_properties(steel_test_critical_memory_writeback_forbidden PROPERTIES LABELS "security;policy;integration")
  steel_add_script_test(steel_test_facet_contract_vtable_model test_facet_contract_vtable_model.sh)
  set_tests_properties(steel_test_facet_contract_vtable_model PROPERTIES LABELS "integration")
  steel_add_script_test(steel_test_typed_signature_contract_enforced test_typed_signature_contract_enforced.sh)
  set_tests_properties(steel_test_typed_signature_contract_enforced PROPERTIES LABELS "security;integration")
  steel_add_script_test(steel_test_signature_c_types_unbounded_params test_signature_c_types_unbounded_params.sh)
  set_tests_properties(steel_test_signature_c_types_unbounded_params PROPERTIES LABELS "integration")
  steel_add_script_test(steel_test_plugin_region_allotment test_plugin_region_allotment.sh)
  set_tests_properties(steel_test_plugin_region_allotment PROPERTIES LABELS "policy;integration")
  steel_add_script_test(steel_test_typed_invoke_auto_marshal test_typed_invoke_auto_marshal.sh)
  set_tests_properties(steel_test_typed_invoke_auto_marshal PROPERTIES LABELS "fast;integration")
  steel_add_script_test(steel_test_proxy_api test_proxy_api.sh)
  set_tests_properties(steel_test_proxy_api PROPERTIES LABELS "fast;integration")
  steel_add_script_test(steel_test_registry_enumeration test_registry_enumeration.sh)
  set_tests_properties(steel_test_registry_enumeration PROPERTIES LABELS "fast;integration")
endif()

install(
  TARGETS steel_runtime steel_contracts_builtin
  EXPORT SteelRuntimeTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
  DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING
    PATTERN "*.h"
    PATTERN "abi_hashes.h" EXCLUDE
)

install(
  FILES
    "${STEEL_ABI_HASH_HDR}"
    "${STEEL_PROXY_GEN_HDR}"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/steel"
)

install(
  EXPORT SteelRuntimeTargets
  FILE SteelRuntimeTargets.cmake
  NAMESPACE Steel::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SteelRuntime"
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SteelRuntimeConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/SteelRuntimeConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SteelRuntime"
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/SteelRuntimeConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/SteelRuntimeConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/SteelRuntimeConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/SteelRuntime"
)
