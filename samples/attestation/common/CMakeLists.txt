# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT attestation_t.h attestation_t.c attestation_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/attestation.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/attestation.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

# Create a library common to each of our two enclaves.
add_library(common OBJECT attestation.cpp crypto.cpp dispatcher.cpp
                          ${CMAKE_CURRENT_BINARY_DIR}/attestation_t.c)

if (WIN32)
  maybe_build_using_clangw(common)
endif ()

target_compile_definitions(common PUBLIC OE_API_VERSION=2)
target_link_libraries(
  common PUBLIC openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
                openenclave::oelibcxx)
target_include_directories(common PUBLIC ${CMAKE_SOURCE_DIR}
                                         ${CMAKE_BINARY_DIR})
