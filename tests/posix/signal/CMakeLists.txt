# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)
add_subdirectory(enc)

add_enclave_test(tests/signal signal_test_host signal_test_enc "nosignal-out")
