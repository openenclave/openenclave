# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_custom_target(tls_server DEPENDS tls_server_host tls_server_enc
                                     tls_server_sign_enc)
