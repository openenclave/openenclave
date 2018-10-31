# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(mem main.c)
target_link_libraries(mem oehost)
target_compile_options(mem PRIVATE -Wconversion -Wpointer-arith)
add_test(tests/mem mem)

