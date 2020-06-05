# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oesign-test-engine SHARED oesign-test-engine.c)

target_include_directories(oesign-test-engine PRIVATE include)
