# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_C_COMPILER_ID GNU)

if (OE_BUILDROOT_BIN AND OE_BUILDROOT_SYSROOT)
    set(CMAKE_PROGRAM_PATH ${OE_BUILDROOT_BIN})
    set(CMAKE_SYSROOT ${OE_BUILDROOT_SYSROOT})
    set(CMAKE_FIND_ROOT_PATH ${OE_BUILDROOT_SYSROOT})
    set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
    set(ENV{PKG_CONFIG_SYSROOT_DIR} ${OE_BUILDROOT_SYSROOT})
endif ()

# When using GCC to compile assembly files.
set(OE_TRUSTZONE_TA_S_FLAGS
    -DASM=1
    -pipe)

set(OE_TRUSTZONE_TA_DEFINES
    -D_XOPEN_SOURCE=700
    -DARM64=1
    -D__LP64__=1)

# When using GCC to compile C/CXX files.
set(OE_TRUSTZONE_TA_C_FLAGS
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
    -fPIC
    -gdwarf)

string(REPLACE ";"
    " "
    OE_TRUSTZONE_TA_C_FLAGS_STRING
    "${OE_TRUSTZONE_TA_C_FLAGS}")

# When using GNU LD for linking.
set(OE_TRUSTZONE_TA_LD_FLAGS "-nostdinc -nostdlib -nodefaultlibs -nostartfiles -pie --sort-section=alignment")

# Path to required bits of the TA Dev Kit.
set(OE_TRUSTZONE_TA_DEV_KIT_CONF                   ${TA_DEV_KIT_DIR}/host_include/conf.h)
set(OE_TRUSTZONE_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE ${TA_DEV_KIT_DIR}/src/ta.ld.S)
set(OE_TRUSTZONE_TA_DEV_KIT_HEADER_SOURCE          ${TA_DEV_KIT_DIR}/src/user_ta_header.c)
set(OE_TRUSTZONE_TA_DEV_KIT_DEFAULT_SIGNING_KEY    ${TA_DEV_KIT_DIR}/keys/default_ta.pem)
set(OE_TRUSTZONE_TA_DEV_KIT_SIGN_TOOL              ${TA_DEV_KIT_DIR}/scripts/sign.py)
