# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (WIN32)
  set(CMAKE_PREFIX_PATH
      "${CMAKE_PREFIX_PATH};C:\\oe_prereqs\\OpenSSL\\x64\\release")
  find_package(OpenSSL REQUIRED)
else ()
  find_package(OpenSSL REQUIRED)
endif ()

add_custom_command(
  OUTPUT secure_verify_u.h secure_verify_u.c secure_verify_args.h
  DEPENDS ../secure_verify.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../secure_verify.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_executable(secure_verify host.cpp evidence.cpp
                      ${CMAKE_CURRENT_BINARY_DIR}/secure_verify_u.c)

add_dependencies(secure_verify secure_verify_enclave_key_pair)

target_include_directories(secure_verify PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                          -I/usr/include/openssl)

target_link_libraries(secure_verify oehost OpenSSL::SSL)

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, secure_verify will be compiled at w2 level.
if (WIN32)
  target_compile_options(secure_verify PRIVATE /W2)
endif ()

# Generate the oecert binary in the the same directory with enclave binary
set_target_properties(secure_verify PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                        "${CMAKE_CURRENT_BINARY_DIR}/..")
