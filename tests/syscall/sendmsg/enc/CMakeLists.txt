# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../sendmsg.edl enclave gen)

##==============================================================================
##
## sendmsg_enc1:
##
##==============================================================================

add_executable(sendmsg_enc1 enc1.c ../client.c ../server.c ${gen})

maybe_build_using_clangw(sendmsg_enc1)

target_link_libraries(sendmsg_enc1 oelibc oeenclave oehostsock)


##==============================================================================
##
## sendmsg_enc2:
##
##==============================================================================

add_executable(sendmsg_enc2 enc2.c ../client.c ../server.c ${gen})

maybe_build_using_clangw(sendmsg_enc2)

target_include_directories(sendmsg_enc2 PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

add_definitions(-DOE_NEED_STDC_NAMES)

target_link_libraries(sendmsg_enc2 oesyscall oeenclave oehostsock)
