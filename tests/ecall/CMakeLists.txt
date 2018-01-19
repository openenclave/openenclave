add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/ecall host/ecallhost ./enc/ecallenc.signed.so)
