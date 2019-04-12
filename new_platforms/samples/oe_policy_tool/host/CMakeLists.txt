# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_host)

set(TARGET oe_policy_tool)

oeedl_file(../oe_policy_tool.edl host GEN C_GEN H_GEN ${OE_PATH}/include)

add_library(json11 STATIC ../../../../3rdparty/json11/json11.cpp)

add_host(
    TARGET ${TARGET}
    SOURCES host.cpp ${GEN})

target_include_directories(${TARGET} PRIVATE ../../../../3rdparty/json11)
target_link_libraries(${TARGET} json11)
