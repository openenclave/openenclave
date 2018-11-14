# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../backtrace.edl enclave gen)

add_executable(backtrace_enc enc.cpp ${gen})

if(USE_DEBUG_MALLOC)
    target_compile_definitions(backtrace_enc PRIVATE OE_USE_DEBUG_MALLOC)
endif()

target_include_directories(backtrace_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(backtrace_enc oelibcxx oeenclave)
target_compile_options(backtrace_enc PRIVATE
    -Wconversion
    -Wpointer-arith)

