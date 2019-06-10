# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecpio STATIC commands.c cpio.c strarr.c)

target_link_libraries(oecpio PRIVATE oelibc oecore)
maybe_build_using_clangw(oecpio)

add_definitions(-DOE_NEED_STDC_NAMES)
