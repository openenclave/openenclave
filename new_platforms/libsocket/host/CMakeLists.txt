include(oeedl_file)

oeedl_file(../../../include/openenclave/socket.edl host GEN C_GEN H_GEN)

if(UNIX)
    set(SRCS linux/socket_host.c)
else()
    set(SRCS win32/socket_host.c)
endif()

add_library(liboesocket_host STATIC ${SRCS} ${GEN})

target_include_directories(liboesocket_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(liboesocket_host PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(liboesocket_host PRIVATE ${PROJECT_SOURCE_DIR}/../include)

if(WIN32)
    target_include_directories(liboesocket_host PRIVATE ${SGXSDKInstallPath}/include)
endif()
