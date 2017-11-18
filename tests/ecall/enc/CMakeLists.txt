include(add_enclave_executable)
add_enclave_executable(ecallenc sign.conf private.pem
	enc.cpp
	)

target_compile_options(ecallenc PRIVATE -Wall -Werror)
