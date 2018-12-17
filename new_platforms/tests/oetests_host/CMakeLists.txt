# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../oetests.edl host GEN C_GEN H_GEN ${OE_PATH}/include)

set(SRCS
    main.cpp
    TrustedAppTest.cpp
    OEEnclaveTest.cpp
    OEHostTest.cpp
    sockets_test.cpp)

add_executable(oetests_host ${SRCS} ${GEN})
target_include_directories(oetests_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(oetests_host gtest oehost oesocket_host oestdio_host)

if(UNIX)
    target_compile_definitions(oetests_host PRIVATE LINUX)
    target_link_libraries(oetests_host teec)
endif()
