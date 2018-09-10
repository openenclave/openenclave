# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_executable(backtrace_enc enc.cpp)

target_link_libraries(backtrace_enc oelibcxx oeenclave)
