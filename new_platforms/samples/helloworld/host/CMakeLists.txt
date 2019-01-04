# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET helloworld_host)

oeedl_file(../helloworld.edl host GEN C_GEN H_GEN ${OE_PATH}/include)

set(SRCS host.c)

add_executable(${TARGET} ${SRCS} ${GEN})
target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${TARGET} oehost oesocket_host oestdio_host)

if(UNIX)
    target_compile_definitions(${TARGET} PRIVATE LINUX)
    target_link_libraries(${TARGET} teec)
elseif(WIN32 AND TZ AND SIM)
    target_link_libraries(${TARGET} oehost_opteesim)
endif()
