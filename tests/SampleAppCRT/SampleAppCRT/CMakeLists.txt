# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(SampleAppCRT SampleAppCRT.cpp)
target_link_libraries(SampleAppCRT oeenclave)
target_compile_options(SampleAppCRT PRIVATE -Wconversion -Wpointer-arith)

