include(oeedl_file)

oeedl_file(${OE_PATH}/include/openenclave/stdio.edl host GEN C_GEN H_GEN)

if(UNIX)
    set(DIR linux)
else()
    set(DIR win32)
endif()

set(SRCS uTcpsFileOcalls_shared.c ${DIR}/ufiles.c ${DIR}/uTcpsFileOcalls.c)

add_library(oestdio_host STATIC ${SRCS} ${GEN})

target_include_directories(oestdio_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(oestdio_host PRIVATE ${OE_PATH}/include)
target_include_directories(oestdio_host PRIVATE ${NP_PATH}/include)

if(UNIX)
    target_compile_definitions(oestdio_host PRIVATE LINUX)
    target_include_directories(oestdio_host PRIVATE ${NP_PATH}/include/linux)
else()
    target_include_directories(oestdio_host PRIVATE ${SGXSDKInstallPath}/include)
endif()
