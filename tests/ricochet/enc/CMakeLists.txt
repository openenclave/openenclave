include(add_enclave_executable)
add_enclave_executable(ricochetenc sign.conf private.pem
	enc.c
	)
