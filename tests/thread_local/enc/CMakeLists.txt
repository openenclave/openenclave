# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../thread_local.edl enclave gen)

add_executable(thread_local_enc enc.cpp externs.cpp ${gen})

target_include_directories(thread_local_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(thread_local_enc oelibcxx oeenclave)
