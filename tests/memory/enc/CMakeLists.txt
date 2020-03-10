# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../memory.edl enclave gen)

add_enclave(TARGET memory_enc UUID 719ff522-610b-43bd-9991-c4d52a91a7e1
  SOURCES
  basic.c
  boundaries.c
  enc.c
  stress.c
  ${gen})

enclave_include_directories(memory_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(memory_enc oelibc)
