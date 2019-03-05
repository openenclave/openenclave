# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oesocket_host)

oeedl_file(${OE_PATH}/include/openenclave/socket.edl host GEN C_GEN H_GEN)

if(UNIX)
    set(DIR linux)
else()
    set(DIR win32)
endif()

set(SRCS ${DIR}/socket_host.c)

add_library(${TARGET} STATIC ${SRCS} ${GEN})
if(UNIX)
    add_dependencies(${TARGET} oeedger8rtool)
endif()

target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(${TARGET} PRIVATE ${OE_PATH}/include)
target_include_directories(${TARGET} PRIVATE ${NP_PATH}/include)

if(WIN32)
    target_link_libraries(${TARGET} PUBLIC ws2_32)

    if(SGX)
        target_include_directories(${TARGET} PRIVATE ${SGXSDKInstallPath}/include)
    endif()
endif()

install(
    TARGETS ${TARGET}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
