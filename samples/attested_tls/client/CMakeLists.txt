# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(enc)
add_subdirectory(host)

add_custom_target(tls_client DEPENDS tls_client_enc tls_client_host tls_client_sign_enc)
