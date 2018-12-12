include(oeedl_file)

oeedl_file(../../../include/openenclave/socket.edl host GEN C_GEN H_GEN)

if(UNIX)
    set(DIR linux)
else()
    set(DIR win32)
endif()

set(SRCS ${DIR}/socket_host.c)

add_library(oesocket_host STATIC ${SRCS} ${GEN})

target_include_directories(oesocket_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(oesocket_host PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(oesocket_host PRIVATE ${PROJECT_SOURCE_DIR}/../include)

if(WIN32)
    target_include_directories(oesocket_host PRIVATE ${SGXSDKInstallPath}/include)
endif()
