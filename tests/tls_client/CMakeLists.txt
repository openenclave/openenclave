# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## tls_client
##
##==============================================================================

add_executable(tls_client tls_client.c common.c client.c)

add_test(NAME tls_client COMMAND tls_client)

target_link_libraries(
    tls_client
     -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

##==============================================================================
##
## tls_server
##
##==============================================================================

add_executable(tls_server tls_server.c server.c common.c)

target_include_directories(tls_server PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(
    tls_server
    -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

add_test(NAME tls_server COMMAND tls_server)
