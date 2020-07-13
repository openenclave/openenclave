# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT allocator_demo_t.h allocator_demo_t.c allocator_demo_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/allocator_demo.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/allocator_demo.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(enclave_default enc.cpp
                               ${CMAKE_CURRENT_BINARY_DIR}/allocator_demo_t.c)
add_executable(enclave_custom enc.cpp
                              ${CMAKE_CURRENT_BINARY_DIR}/allocator_demo_t.c)

if (WIN32)
  maybe_build_using_clangw(enclave_default)
  maybe_build_using_clangw(enclave_custom)
endif ()

target_compile_definitions(enclave_default PUBLIC OE_API_VERSION=2)
target_compile_definitions(enclave_custom PUBLIC OE_API_VERSION=2)

# Need for the generated file allocator_demo_t.h
target_include_directories(enclave_default PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(enclave_custom PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (LVI_MITIGATION MATCHES ControlFlow)
  # Helper to enable compiler options for LVI mitigation.
  apply_lvi_mitigation(enclave_default)
  apply_lvi_mitigation(enclave_custom)

  # Link against LVI-mitigated libraries.
  target_link_libraries(enclave_default openenclave::oeenclave-lvi-cfg
                        openenclave::oelibcxx-lvi-cfg)
  target_link_libraries(
    enclave_custom openenclave::oeenclave-lvi-cfg
    # Specify pluggable allocator library
    openenclave::oesnmalloc-lvi-cfg openenclave::oelibcxx-lvi-cfg)
else ()
  target_link_libraries(enclave_default openenclave::oeenclave
                        openenclave::oelibcxx)
  target_link_libraries(
    enclave_custom openenclave::oeenclave
    # Specify pluggable allocator library
    openenclave::oesnmalloc openenclave::oelibcxx)
endif ()
