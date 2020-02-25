# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(tls_client tls_client.c main.c)

add_test(NAME tls_client COMMAND tls_client)

#target_include_directories(tls_client ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(
    tls_client
     -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)
