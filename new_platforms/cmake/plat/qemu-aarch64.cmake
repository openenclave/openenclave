# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(${CMAKE_CURRENT_LIST_DIR}/../linux-aarch64-v6.cmake)

# When using GCC to compile assembly files.
set(OE_TA_S_FLAGS
    -DASM=1
    -pipe
)

if("${CMAKE_BUILD_TYPE}" STREQUAL "" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND OE_TA_S_FLAGS -g)
endif()

# When using GCC to compile C files.
set(OE_TA_C_FLAGS_DEFINITIONS
    -D_XOPEN_SOURCE=700
    -DARM64=1
    -D__LP64__=1)

set(OE_TA_C_FLAGS_WARNINGS
    -Wno-missing-braces
    -Wno-parentheses
    -Wno-unknown-pragmas
    -Wno-conversion
    -Wno-unused-parameter
    -Wno-sign-compare
    #-Wno-jump-misses-init
    -Wno-maybe-uninitialized
    -Wno-unknown-pragmas
    -Wno-unused-but-set-variable
    -Wno-unused-function
    -Wno-unused-value
    -Wno-unused-variable)

set(OE_TA_C_FLAGS_OPTIONS
    -mstrict-align
    -nostdinc
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    -fno-builtin-memcpy
    -fno-builtin-memset
    -ffreestanding
    #-fexcess-precision=standard
    -frounding-math
    -fpie
    -fPIC
    #-std=gnu99
    -include ${OE_TA_CONF})

if("${CMAKE_BUILD_TYPE}" STREQUAL "" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND OE_TA_C_FLAGS_OPTIONS -g3)
else()
    list(APPEND OE_TA_C_FLAGS_OPTIONS -Os)
endif()

set(OE_TA_C_FLAGS
    ${OE_TA_C_FLAGS_DEFINITIONS}
    ${OE_TA_C_FLAGS_WARNINGS}
    ${OE_TA_C_FLAGS_OPTIONS})
