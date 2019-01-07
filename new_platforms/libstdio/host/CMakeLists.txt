# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oestdio_host)

oeedl_file(${OE_PATH}/include/openenclave/stdio.edl host GEN C_GEN H_GEN)

if(UNIX)
    set(DIR linux)
else()
    set(DIR win32)
endif()

set(SRCS uTcpsFileOcalls_shared.c ${DIR}/ufiles.c ${DIR}/uTcpsFileOcalls.c)

add_library(${TARGET} STATIC ${SRCS} ${GEN})

target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(${TARGET} PRIVATE ${OE_PATH}/include)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include)

if(UNIX)
    target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include/linux)
elseif(WIN32 AND SGX)
    target_include_directories(${TARGET} PRIVATE ${SGXSDKInstallPath}/include)
endif()
