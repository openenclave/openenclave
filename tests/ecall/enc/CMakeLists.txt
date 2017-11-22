include(add_enclave_executable)
add_enclave_executable(ecallenc sign.conf private.pem
	enc.cpp
	)
