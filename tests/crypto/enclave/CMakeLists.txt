add_subdirectory(enc)
add_subdirectory(host)
add_test(tests/crypto/enclave host/cryptohost ./enc/cryptoenc.signed.so)
