include(add_enclave_executable)
add_enclave_executable(NestedCallEnc sign.conf private.pem
    enc.c
    )
