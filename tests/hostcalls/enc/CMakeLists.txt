include(add_enclave_executable)
add_enclave_executable(hostcallsenc sign.conf private.pem
    enc.cpp
    )
