# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(test_host_verify host.cpp)

# Copy bad test data
configure_file(../data/sgx_cert_ec_bad.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_ec_bad.der COPYONLY)
configure_file(../data/sgx_cert_rsa_bad.der
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_cert_rsa_bad.der COPYONLY)
configure_file(../data/sgx_report_bad.bin
               ${CMAKE_CURRENT_BINARY_DIR}/sgx_report_bad.bin COPYONLY)
configure_file(../data/tdx_quote.bin ${CMAKE_CURRENT_BINARY_DIR}/tdx_quote.bin
               COPYONLY)
configure_file(../data/tdx_quote_v5.bin
               ${CMAKE_CURRENT_BINARY_DIR}/tdx_quote_v5.bin COPYONLY)

# Copy TD relaunch quote and endorsement
configure_file(
  ../data/tdx_quote-moduleupdate-seamldr5.dat
  ${CMAKE_CURRENT_BINARY_DIR}/tdx_quote-moduleupdate-seamldr5.dat COPYONLY)
configure_file(../data/tdx_endorsement.bin
               ${CMAKE_CURRENT_BINARY_DIR}/tdx_endorsement.bin COPYONLY)

target_link_libraries(test_host_verify oehostverify)
