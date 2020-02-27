# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## tlscli
##
##==============================================================================

add_executable(tlscli tlscli.c common.c client.c)

add_test(NAME tlscli COMMAND tlscli)

target_link_libraries(
    tlscli
     -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

##==============================================================================
##
## tlssrv
##
##==============================================================================

add_executable(tlssrv tlssrv.c server.c common.c)

target_include_directories(tlssrv PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(
    tlssrv
    -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

add_test(NAME tlssrv COMMAND tlssrv)
