add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/file host/filehost ./enc/fileenc.signed.so)
