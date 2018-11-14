# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(SampleApp CallWrappers.cpp SampleApp.cpp)
target_link_libraries(SampleApp oeenclave)
target_compile_options(SampleApp PRIVATE -Wconversion -Wpointer-arith)
