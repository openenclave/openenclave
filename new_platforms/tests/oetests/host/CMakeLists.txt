# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

set(TARGET oetests_host)

oeedl_file(${CMAKE_CURRENT_LIST_DIR}/../oetests.edl host GEN C_GEN H_GEN ${OE_PATH}/include)

add_host(
    TARGET ${TARGET}
    SOURCES
        main.cpp
        TrustedAppTest.cpp
        OEEnclaveTest.cpp
        OEHostTest.cpp
        sockets_test.cpp
        ${GEN})

target_link_libraries(${TARGET} gtest)
