# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(test_host_verify host.cpp)

# Copy bad test data
configure_file(../data/sgx_cert_ec_bad.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_ec_bad.der COPYONLY)
configure_file(../data/sgx_cert_rsa_bad.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_rsa_bad.der COPYONLY)
configure_file(../data/sgx_report_bad.bin
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_report_bad.bin COPYONLY)

target_link_libraries(test_host_verify oehostverify)
