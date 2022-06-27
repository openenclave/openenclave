# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (WIN32)
  set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};C:\\oe_prereqs\\OpenSSL\\x64\\release")
  find_package(OpenSSL REQUIRED)
else ()
  find_package(OpenSSL REQUIRED)
endif ()

add_executable(tls_non_enc_client client.cpp cert_verify_config.cpp
                                  ../common/verify_callback.cpp)

add_dependencies(tls_non_enc_client tls_server_sign_enc)

target_include_directories(
  tls_non_enc_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                             ${CMAKE_CURRENT_BINARY_DIR} -I/usr/include/openssl)

target_link_libraries(tls_non_enc_client openenclave::oehost OpenSSL::SSL)

add_dependencies(tls_non_enc_client tls_server)
