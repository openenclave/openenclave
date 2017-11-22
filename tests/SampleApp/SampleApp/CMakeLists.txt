include(add_enclave_executable)
add_enclave_executable(SampleApp sign.conf private.pem
	CallWrappers.cpp
	SampleApp.cpp
	)
