# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

oeedl_file(../backtrace.edl enclave gen)

add_enclave(TARGET backtrace_enc CXX SOURCES enc.cpp ${gen})

if(USE_DEBUG_MALLOC)
    target_compile_definitions(backtrace_enc PRIVATE OE_USE_DEBUG_MALLOC)
endif()

target_include_directories(backtrace_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
