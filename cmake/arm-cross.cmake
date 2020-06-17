# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_C_COMPILER_ID GNU)

# Allow the developer to target a runtime environment other than that of the
# build host.
if (OE_PROGRAM_PATH AND OE_SYSROOT)
  set(CMAKE_PROGRAM_PATH ${OE_PROGRAM_PATH})
  set(CMAKE_SYSROOT ${OE_SYSROOT})
  set(CMAKE_FIND_ROOT_PATH ${OE_SYSROOT})
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(ENV{PKG_CONFIG_SYSROOT_DIR} ${OE_SYSROOT})
endif ()

# When using GCC to compile assembly files.
set(OE_TZ_TA_S_FLAGS -DASM=1 -pipe)

# When using GCC to compile C/CXX files.
set(OE_TZ_TA_C_FLAGS
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
    -fPIC
    -gdwarf)

# Path to required bits of the TA Dev Kit.
set(OE_TZ_TA_DEV_KIT_CONF ${OE_TA_DEV_KIT_DIR}/host_include/conf.h)
set(OE_TZ_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE ${OE_TA_DEV_KIT_DIR}/src/ta.ld.S)
set(OE_TZ_TA_DEV_KIT_HEADER_SOURCE ${OE_TA_DEV_KIT_DIR}/src/user_ta_header.c)
set(OE_TZ_TA_DEV_KIT_DEFAULT_SIGNING_KEY
    ${OE_TA_DEV_KIT_DIR}/keys/default_ta.pem)
set(OE_TZ_TA_DEV_KIT_SIGN_TOOL ${OE_TA_DEV_KIT_DIR}/scripts/sign.py)

# Path to OP-TEE OS.
set(OE_TZ_OPTEE_SRC ${PROJECT_SOURCE_DIR}/3rdparty/optee/optee_os)

# Path to OP-TEE's user-mode library (libutee).
set(OE_TZ_LIBUTEE_SRC ${OE_TZ_OPTEE_SRC}/lib/libutee)
set(OE_TZ_LIBUTEE_INC ${OE_TZ_LIBUTEE_SRC}/include)

# Path to OP-TEE's user-mode utilities (libutils).
set(OE_TZ_LIBUTILS_SRC ${OE_TZ_OPTEE_SRC}/lib/libutils)

# Path to OP-TEE's user-mode C runtime library (part of libutils).
set(OE_TZ_LIBUTILS_ISOC_INC ${OE_TZ_LIBUTILS_SRC}/isoc/include)

# Path to OP-TEE's user-mode C runtime library extenions (part of libutils).
set(OE_TZ_LIBUTILS_EXT_SRC ${OE_TZ_LIBUTILS_SRC}/ext)
set(OE_TZ_LIBUTILS_EXT_INC ${OE_TZ_LIBUTILS_EXT_SRC}/include)

# Path to OP-TEE's user-mode math library (libmpa).
set(OE_TZ_LIBMPA_SRC ${OE_TZ_OPTEE_SRC}/lib/libmpa)
set(OE_TZ_LIBMPA_INC ${OE_TZ_LIBMPA_SRC}/include)

# Path to OP-TEE's non-secure user-mode client.
set(OE_TZ_OPTEE_CLIENT_SRC ${PROJECT_SOURCE_DIR}/3rdparty/optee/optee_client)
set(OE_TZ_OPTEE_CLIENT_INC ${OE_TZ_OPTEE_CLIENT_SRC}/public)
