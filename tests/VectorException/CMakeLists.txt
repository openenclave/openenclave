add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/VectorException host/VectorExceptionHost ./enc/VectorExceptionEnc.signed.so)
set_tests_properties(tests/VectorException PROPERTIES SKIP_RETURN_CODE 2)