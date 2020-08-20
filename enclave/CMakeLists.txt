# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(attestation)
add_subdirectory(core)
add_subdirectory(crypto)

if (OE_SGX)
  set(PLATFORM_SRC sgx/start.S)
elseif (OE_TRUSTZONE)
  set(PLATFORM_SRC optee/start.S)
endif ()

enclave_enable_code_coverage(oeenclave)

add_enclave_library(oeenclave STATIC link.c ${PLATFORM_SRC})

maybe_build_using_clangw(oeenclave)

# Retain the original behavior (i.e., oeattestation was part of oeenclave).
enclave_link_libraries(oeenclave PUBLIC oeattestation)

# Add location of the oeedger8r-generated trusted headers for internal
# functions implemented via EDL files.
enclave_include_directories(oeenclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/core)

set_enclave_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
install_enclaves(
  TARGETS
  oeenclave
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
