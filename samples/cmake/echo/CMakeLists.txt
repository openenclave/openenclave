add_subdirectory(enc)
add_subdirectory(host)

add_test(samples/cmake/echo host/samples-echohost ./enc/samples-echoenc.signed.so)
