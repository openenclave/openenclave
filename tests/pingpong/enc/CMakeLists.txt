include(oeidl_file)
include(add_enclave_executable)

oeidl_file(../pingpong.idl enclave gen)
add_enclave_executable(pingpongenc sign.conf private.pem
	enc.cpp
	${gen}
	)

target_include_directories(pingpongenc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpongenc oeidl oelibc)
