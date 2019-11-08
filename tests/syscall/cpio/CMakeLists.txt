# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oecpio STATIC commands.c cpio.c strarr.c)

target_link_libraries(oecpio PRIVATE oelibc oecore)

maybe_build_using_clangw(oecpio)
