# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(hostcrypto 
    main.c
    ../asn1_tests.c
    ../base64_tests.c
    ../crl_tests.c
    ../ec_tests.c
    ../hash.c
    ../random_tests.c
    ../rsa_tests.c
    ../sha_tests.c
    ../tests.c)

target_link_libraries(hostcrypto oehost)

add_test(tests/crypto/host hostcrypto)

