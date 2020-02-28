# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(tlscli tlscli.c cli.c)

target_link_libraries(tlscli
    -L/usr/lib/x86_64-linux-gnu -lmbedtls -lmbedx509 -lmbedcrypto)

set(CERT "${CMAKE_CURRENT_BINARY_DIR}/../gencreds/cert.der")
set(PRIVATE_KEY "${CMAKE_CURRENT_BINARY_DIR}/../gencreds/private_key.pem")

add_test(NAME tlscli COMMAND tlscli ${CERT} ${PRIVATE_KEY})
