add_subdirectory(enc)
add_subdirectory(host)

add_test(samples/cmake/idl-file host/samples-filehost ./enc/samples-fileenc.signed.so)
