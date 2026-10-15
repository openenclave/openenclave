# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Explicit reviewable patch order; reassess each local change on libc++ upgrades.
set(LIBCXX_HEADER_PATCHES
    ${CMAKE_CURRENT_LIST_DIR}/type_traits.patch
    ${CMAKE_CURRENT_LIST_DIR}/regex.patch
    ${CMAKE_CURRENT_LIST_DIR}/string.patch
    ${CMAKE_CURRENT_LIST_DIR}/__hash_table.patch
    ${CMAKE_CURRENT_LIST_DIR}/functional.patch)
