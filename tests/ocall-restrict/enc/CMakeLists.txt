include(add_enclave_executable)
add_enclave_executable(ocall-restrict-enc sign.conf private.pem
    enc.cpp
    )
target_link_libraries(ocall-restrict-enc oelibc)
