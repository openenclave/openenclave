add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/ocall host/ocallhost ./enc/ocallenc.signed.so)
