# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../safecrt.edl enclave gen)

add_enclave(TARGET safecrt_enc CXX
  SOURCES ../common/test.cpp enc.cpp ${gen})

target_include_directories(safecrt_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
