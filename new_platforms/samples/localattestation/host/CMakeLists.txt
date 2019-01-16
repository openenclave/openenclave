# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_host)

set(TARGET localattestation_host)

oeedl_file(../localattestation.edl host GEN C_GEN H_GEN ${OE_PATH}/include)

set(SRCS host.c ${GEN})

add_host(${TARGET} ${SRCS})
