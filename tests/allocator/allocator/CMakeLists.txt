# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(test_allocator STATIC allocator.c)

target_compile_options(test_allocator PUBLIC -fPIC -nostdinc)

target_link_libraries(test_allocator PUBLIC oe_includes)
