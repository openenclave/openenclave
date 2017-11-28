include(add_enclave_executable)
add_enclave_executable(mbedenc sign.conf private.pem
	enc.c
	)

target_link_libraries(mbedenc mbedcrypto oelibc)
