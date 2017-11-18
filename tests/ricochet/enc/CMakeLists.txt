include(add_enclave_executable)
add_enclave_executable(ricochetenc sign.conf private.pem
	enc.c
	)

target_compile_options(ricochetenc PRIVATE -Wall -Werror)
