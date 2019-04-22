# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecpio STATIC commands.c cpio.c strarr.c)

target_link_libraries(oecpio PRIVATE oecore)

target_include_directories(oecpio PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

add_definitions(-DOE_NEED_STDC_NAMES)
