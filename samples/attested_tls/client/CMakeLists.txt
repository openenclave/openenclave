# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(enc/${OE_CRYPTO_LIB})
add_subdirectory(host)

add_custom_target(tls_client DEPENDS tls_client_enc tls_client_host
                                     tls_client_sign_enc)
