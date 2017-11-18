include(add_enclave_executable)
add_enclave_executable(stdcenc sign.conf private.pem
	enc.cpp
	)

target_compile_options(stdcenc PRIVATE -Wall -Werror
	-Wno-error=unused-but-set-variable
	-Wno-error=unused-variable
	-fno-builtin-strcpy
	-fno-builtin-strcat
	-fno-builtin-memcpy
	-fno-builtin-memset
	)

target_link_libraries(stdcenc -Wl,--whole-archive oelibc -Wl,--no-whole-archive)
