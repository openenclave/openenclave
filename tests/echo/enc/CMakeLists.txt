include(add_enclave_executable)
add_enclave_executable(echoenc sign.conf private.pem
	enc.c
	)
