# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## gencert
##
##==============================================================================

add_subdirectory(gencreds)

##==============================================================================
##
## tlscli
##
##==============================================================================

add_executable(tlscli tlscli.c client.c)

target_link_libraries(tlscli
    -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

##==============================================================================
##
## tlssrv
##
##==============================================================================

add_executable(tlssrv tlssrv.c server.c)

target_include_directories(tlssrv PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(tlssrv
    -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)
