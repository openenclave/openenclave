include(add_enclave_executable)
add_enclave_executable(ocallenc sign.conf private.pem
	enc.cpp
	)
