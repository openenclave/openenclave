add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/echo host/echohost ./enc/echoenc.signed.so)
