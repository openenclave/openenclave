add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/thread host/threadhost ./enc/threadenc.signed.so)
