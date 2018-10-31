# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../hostcalls.edl enclave gen)

add_executable(hostcalls_enc enc.cpp ${gen})

target_include_directories(hostcalls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hostcalls_enc oeenclave)
target_compile_options(hostcalls_enc PRIVATE -Wconversion -Wpointer-arith)
