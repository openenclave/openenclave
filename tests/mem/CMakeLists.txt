# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(mem main.c)
target_link_libraries(mem oehost)
add_test(tests/mem mem)
