include(add_enclave_executable)
add_enclave_executable(SampleAppCRT sign.conf private.pem
	SampleAppCRT.cpp
	)
target_link_libraries(SampleAppCRT oelibc)
