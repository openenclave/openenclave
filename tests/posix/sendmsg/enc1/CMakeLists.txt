# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../sendmsg.edl enclave gen)

add_executable(sendmsg_enc1 enc.c ../client.c ../server.c ${gen})
maybe_build_using_clangw(sendmsg_enc1)

target_link_libraries(sendmsg_enc1 oelibc oeenclave oehostsock)
