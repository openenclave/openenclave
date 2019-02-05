# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeallocator STATIC allocator.c)

target_link_libraries(oeallocator PUBLIC oelibc)
