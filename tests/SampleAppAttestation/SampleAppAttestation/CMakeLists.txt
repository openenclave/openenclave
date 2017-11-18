include(add_enclave_executable)
add_enclave_executable(SampleAppAttestation sign.conf private.pem
	SampleAppAttestation.cpp
	)

target_compile_options(SampleAppAttestation PRIVATE -Wall -Werror)
target_link_libraries(SampleAppAttestation oelibc)
