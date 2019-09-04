# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(test_host_verify host.cpp)

# Create private/public key pairs using openssl
add_custom_command(OUTPUT keyec.pem publicec.pem
  COMMAND openssl ecparam -name prime256v1 -genkey -noout -out keyec.pem
  COMMAND openssl ec -in keyec.pem -pubout -out publicec.pem)
add_custom_command(OUTPUT keyrsa.pem publicrsa.pem
  COMMAND openssl genrsa -out keyrsa.pem 2048
  COMMAND openssl rsa -in keyrsa.pem -outform PEM -pubout -out publicrsa.pem)

# Copy bad test data
configure_file(../data/sgx_cert_ec_bad.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_ec_bad.der COPYONLY)
configure_file(../data/sgx_cert_rsa_bad.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_rsa_bad.der COPYONLY)
configure_file(../data/sgx_report_bad.bin
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_report_bad.bin COPYONLY)

target_link_libraries(test_host_verify oehostverify)
