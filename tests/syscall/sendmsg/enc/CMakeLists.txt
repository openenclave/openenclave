# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../sendmsg.edl enclave gen)

##==============================================================================
##
## sendmsg_enc:
##
##==============================================================================

add_executable(sendmsg_enc enc.c ../client.c ../server.c ${gen})

maybe_build_using_clangw(sendmsg_enc)

target_link_libraries(sendmsg_enc oelibc oeenclave oehostsock)
