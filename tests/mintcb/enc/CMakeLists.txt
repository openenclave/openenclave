# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mintcb.edl enclave gen)

add_executable(mintcb_enc enc.c start.S ${gen})

maybe_build_using_clangw(mintcb_enc)

target_include_directories(mintcb_enc PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc
    ${CMAKE_CURRENT_BINARY_DIR})

add_definitions(-DOE_NEED_STDC_NAMES)

target_link_libraries(mintcb_enc oecore)
