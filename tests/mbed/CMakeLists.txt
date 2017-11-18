add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/mbed host/mbedhost ./enc/mbedenc.signed.so)
