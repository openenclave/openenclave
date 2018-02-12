include(add_enclave_executable)
add_enclave_executable(VectorExceptionEnc sign.conf private.pem
    enc.c
    )
