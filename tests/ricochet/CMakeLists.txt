add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/ricochet host/ricochethost ./enc/ricochetenc.signed.so)
