# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_host)

set(TARGET socketserver_host)

oeedl_file(../sockets.edl host GEN C_GEN H_GEN ${OE_PATH}/include)

set(SRCS main.c ${GEN})

add_host(${TARGET} ${SRCS})
