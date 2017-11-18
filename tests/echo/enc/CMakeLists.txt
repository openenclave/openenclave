include(add_enclave_executable)
add_enclave_executable(echoenc sign.conf private.pem
	enc.c
	)

target_compile_options(echoenc PRIVATE -Wall -Werror)
