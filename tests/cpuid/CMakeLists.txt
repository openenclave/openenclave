# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(cpuid main.cpp)
target_link_libraries(cpuid oehost)

add_test(NAME tests/cpuid COMMAND ./cpuid)
