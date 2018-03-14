add_executable(hostcrypto main.c)
target_link_libraries(hostcrypto oecryptohost)
add_test(tests/crypto/host hostcrypto)

