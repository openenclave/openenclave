# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

add_enclave_test(tests/oegencert oegencert_host oegencert_enc)
