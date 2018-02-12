include(add_enclave_executable)
add_enclave_executable(samples-helloenc hello.conf private.pem
    enc.c
    )
target_link_libraries(samples-helloenc oelibc)
