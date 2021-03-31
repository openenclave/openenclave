# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_package(OpenSSL REQUIRED)

add_custom_command(
  OUTPUT oecert_u.h oecert_u.c oecert_args.h
  DEPENDS ../oecert.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecert.edl
          --search-path ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_executable(oecert host.cpp evidence.cpp
                      ${CMAKE_CURRENT_BINARY_DIR}/oecert_u.c)

target_include_directories(oecert PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                          -I/usr/include/openssl)

target_link_libraries(oecert oehost OpenSSL::SSL)

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, oecertdump will be compiled at w2 level.
if (WIN32)
  target_compile_options(oecert PRIVATE /W2)
endif ()

# Generate the oecert binary in the the same directory with enclave binary
set_target_properties(oecert PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                        "${CMAKE_CURRENT_BINARY_DIR}/..")
