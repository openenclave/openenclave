# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../sendmsg.edl enclave gen)

##==============================================================================
##
## sendmsg_enc:
##
##==============================================================================

add_enclave_executable(sendmsg_enc enc.c ../client.c ../server.c ${CMAKE_CURRENT_BINARY_DIR}/sendmsg_t.c)

maybe_build_using_clangw(sendmsg_enc)

enclave_link_libraries(sendmsg_enc oelibc oeenclave oehostsock)
