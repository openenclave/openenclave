# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(threadcxx_enc enc.cpp cond_tests.cpp)
target_compile_options(threadcxx_enc PRIVATE
    --std=c++11)
target_link_libraries(threadcxx_enc oelibcxx oeenclave)
