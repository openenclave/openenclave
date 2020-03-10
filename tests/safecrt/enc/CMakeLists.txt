# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../safecrt.edl enclave gen)

add_enclave(TARGET safecrt_enc UUID 91dc6667-7a33-4bbc-ab3e-ab4fca5215b7 CXX
  SOURCES ../common/test.cpp enc.cpp ${gen})

enclave_include_directories(safecrt_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
