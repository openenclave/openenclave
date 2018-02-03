add_subdirectory(enc)
add_subdirectory(host)

add_test(samples/cmake/hello host/samples-hellohost ./enc/samples-helloenc.signed.so)
