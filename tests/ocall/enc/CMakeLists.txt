# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../ocall.edl enclave gen)

add_executable(ocall_enc enc.cpp ${gen})

target_include_directories(ocall_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ocall_enc oeenclave)
