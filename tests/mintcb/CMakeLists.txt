# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

add_subdirectory(enc)

add_enclave_test(tests/mintcb mintcb_host mintcb_enc)
