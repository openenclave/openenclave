# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(${OE_PATH}/include/openenclave/socket.edl host GEN C_GEN H_GEN)

if(UNIX)
    set(DIR linux)
else()
    set(DIR win32)
endif()

set(SRCS ${DIR}/socket_host.c)

add_library(oesocket_host STATIC ${SRCS} ${GEN})

target_include_directories(oesocket_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(oesocket_host PRIVATE ${OE_PATH}/include)
target_include_directories(oesocket_host PRIVATE ${NP_PATH}/include)

if(WIN32)
    target_link_libraries(oesocket_host PUBLIC ws2_32)

    if(SGX)
        target_include_directories(oesocket_host PRIVATE ${SGXSDKInstallPath}/include)
    endif()
endif()
