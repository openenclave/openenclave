# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../memory.edl enclave gen)

add_enclave(TARGET memory_enc
  SOURCES
  basic.c
  boundaries.c
  enc.c
  stress.c
  ${gen})


target_include_directories(memory_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(memory_enc oelibc)
