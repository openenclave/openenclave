# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_executable(log_enc enc.cpp)

if(USE_DEBUG_MALLOC)
    target_compile_definitions(log_enc PRIVATE OE_USE_DEBUG_MALLOC)
endif()

target_link_libraries(log_enc oelibcxx oeenclave)
