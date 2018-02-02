add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/NestedCall host/NestedCallHost ./enc/NestedCallEnc.signed.so)
