add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/report host/reporthost ./enc/reportenc.signed.so)
