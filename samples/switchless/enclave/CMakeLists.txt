# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT switchless_t.h switchless_t.c switchless_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/switchless.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/switchless.edl)

add_executable(enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/switchless_t.c)

if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file switchless_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclave openenclave::oeenclave openenclave::oelibc)
