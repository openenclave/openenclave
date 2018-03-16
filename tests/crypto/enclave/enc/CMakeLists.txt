include(add_enclave_executable)

add_enclave_executable(
    cryptoenc 
    sign.conf 
    private.pem
    enc.c)

#target_link_libraries(cryptoenc oecrypto mbedcrypto oelibc)
target_link_libraries(cryptoenc oecrypto)
