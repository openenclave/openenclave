add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/tester host/testerhost ./enc/testerenc.signed.so)
