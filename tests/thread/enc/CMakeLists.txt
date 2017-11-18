include(add_enclave_executable)
add_enclave_executable(threadenc sign.conf private.pem
	enc.cpp
	)

target_compile_options(threadenc PRIVATE
	-fno-builtin-strcpy
	-fno-builtin-strcat
	-fno-builtin-memcpy
	-fno-builtin-memset
	-Wall -Werror)

target_link_libraries(threadenc oelibc)

