# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oelibmalloc STATIC libmalloc.c)

target_link_libraries(oelibmalloc PUBLIC oelibc)
