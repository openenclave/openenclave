# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../backtrace.edl enclave gen)

add_enclave(TARGET backtrace_enc UUID c21d0c84-a32b-430a-ad9a-7bf8b47eff0c CXX SOURCES enc.cpp ${gen})

if(USE_DEBUG_MALLOC)
    target_compile_definitions(backtrace_enc PRIVATE OE_USE_DEBUG_MALLOC)
endif()

target_include_directories(backtrace_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
