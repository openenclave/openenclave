# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_host)

set(TARGET [[project-name]])

oeedl_file(../[[project-name]].edl host GEN C_GEN H_GEN ${OE_PATH}/include)

add_host(
    TARGET ${TARGET}
    SOURCES main.c host.c ${GEN})
 