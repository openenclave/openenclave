# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Disable on Windows until host-side crypto is implemented
if (UNIX)
add_executable(hostcrypto
    main.c
    ../../../common/sgx/rand.S
    ../read_file.c
    ../asn1_tests.c
    ../crl_tests.c
    ../ec_tests.c
    ../hash.c
    ../hmac_tests.c
    ../kdf_tests.c
    ../random_tests.c
    ../rdrand_test.c
    ../rsa_tests.c
    ../sha_tests.c
    ../tests.c
    ../utils.c)

add_dependencies(hostcrypto crypto_test_data)
target_link_libraries(hostcrypto oehost)
add_test(tests/crypto/host hostcrypto)

endif()
