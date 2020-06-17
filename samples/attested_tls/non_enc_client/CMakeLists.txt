# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_package(OpenSSL REQUIRED)

add_executable(tls_non_enc_client client.cpp verify_callback.cpp)

add_dependencies(tls_non_enc_client tls_server_sign_enc)

target_include_directories(
  tls_non_enc_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                             ${CMAKE_CURRENT_BINARY_DIR} -I/usr/include/openssl)

target_link_libraries(tls_non_enc_client openenclave::oehost OpenSSL::SSL)

add_dependencies(tls_non_enc_client tls_server)
