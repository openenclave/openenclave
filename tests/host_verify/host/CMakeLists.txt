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

if (OE_SGX)
  add_dependencies(test_host_verify oecert)
  add_custom_target(sgx_ec_cert
    COMMAND oecert
            ${CMAKE_BINARY_DIR}/tests/tools/oecert/enc/oecert_enc
            --cert keyec.pem publicec.pem --out sgx_cert_ec.der
    DEPENDS keyec.pem publicec.pem)
  add_custom_target(sgx_rsa_cert
    COMMAND oecert
            ${CMAKE_BINARY_DIR}/tests/tools/oecert/enc/oecert_enc
            --cert keyrsa.pem publicrsa.pem --out sgx_cert_rsa.der
    DEPENDS keyrsa.pem publicrsa.pem)
  add_custom_target(sgx_report
    COMMAND oecert
            ${CMAKE_BINARY_DIR}/tests/tools/oecert/enc/oecert_enc
            --report --out sgx_report.bin)

  add_dependencies(sgx_ec_cert oecert)
  add_dependencies(sgx_rsa_cert oecert)
  add_dependencies(sgx_report oecert)
  add_dependencies(test_host_verify sgx_ec_cert sgx_rsa_cert sgx_report)
else()
  # TODO: Test running in non-SGX machine.  Need to get report from an SGX machine.
  # 1. Create ACCVM and connect to it.
  # 2. Run the above commands to generate the keys/certs/reports.
  # 3. Copy over the certs and report.
endif()

# Copy bad test data
configure_file(../data/sgx_cert_ec_bad_tcb.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_ec_bad_tcb.der COPYONLY)
configure_file(../data/sgx_cert_rsa_bad_tcb.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_rsa_bad_tcb.der COPYONLY)
configure_file(../data/sgx_report_bad_tcb.bin
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_report_bad_tcb.bin COPYONLY)

#target_include_directories(test_host_verify PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_host_verify oehostverify)
