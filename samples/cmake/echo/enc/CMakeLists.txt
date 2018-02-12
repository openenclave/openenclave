include(add_enclave_executable)
add_enclave_executable(samples-echoenc echo.conf private.pem
    enc.c
    )
