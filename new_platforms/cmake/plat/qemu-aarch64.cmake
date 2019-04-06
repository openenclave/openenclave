# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(${CMAKE_CURRENT_LIST_DIR}/../linux-aarch64-v6.cmake)

# When using GCC to compile assembly files.
set(OE_TA_S_FLAGS
    -DASM=1
    -pipe)

if("${CMAKE_BUILD_TYPE}" STREQUAL "" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND OE_TA_S_FLAGS -g)
endif()

# When using GCC to compile C/CXX files.
set(OE_TA_C_FLAGS
    -D_XOPEN_SOURCE=700
    -DARM64=1
    -D__LP64__=1
    -mstrict-align
    -nostdinc
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    -fno-builtin-memcpy
    -fno-builtin-memset
    -ffreestanding
    -funwind-tables
    -fpie
    -fPIC)

if("${CMAKE_BUILD_TYPE}" STREQUAL "" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND OE_TA_C_FLAGS -g3)
else()
    list(APPEND OE_TA_C_FLAGS -gdwarf -Os)
endif()

# When using GCC for linking.
set(OE_TA_LD_FLAGS "-nostdinc -nostdlib -nodefaultlibs -nostartfiles -pie --sort-section=alignment")

# Path to required bits of the TA Dev Kit.
set(OE_TA_DEV_KIT_CONF                   ${TA_DEV_KIT_DIR}/host_include/conf.h)
set(OE_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE ${TA_DEV_KIT_DIR}/src/ta.ld.S)
set(OE_TA_DEV_KIT_HEADER_SOURCE          ${TA_DEV_KIT_DIR}/src/user_ta_header.c)
set(OE_TA_DEV_KIT_DEFAULT_SIGNING_KEY    ${TA_DEV_KIT_DIR}/keys/default_ta.pem)
set(OE_TA_DEV_KIT_SIGN_TOOL              ${TA_DEV_KIT_DIR}/scripts/sign.py)
