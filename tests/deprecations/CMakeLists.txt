# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_executable(deprecations_enc enc.c)

target_link_libraries(deprecations_enc oeenclave)

# There is no test program to run since this is just a compile time test.
add_test(tests/deprecations true)
