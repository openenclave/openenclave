include(add_enclave_executable)
add_enclave_executable(reportenc sign.conf private.pem
	enc.cpp
	)

target_compile_options(echoenc PRIVATE -Wall -Werror)
