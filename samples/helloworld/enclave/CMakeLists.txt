# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# TODO: Where is the best place to set this

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(OUTPUT helloworld_t.h helloworld_t.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/helloworld.edl)

add_executable(enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/helloworld_t.c)

if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file helloworld_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclave openenclave::oeenclave openenclave::oelibc)
