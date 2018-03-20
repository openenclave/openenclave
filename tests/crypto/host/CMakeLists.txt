# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(hostcrypto main.c)
target_link_libraries(hostcrypto oecryptohost)
add_test(tests/crypto/host hostcrypto)

