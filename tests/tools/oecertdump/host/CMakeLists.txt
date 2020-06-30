# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_package(OpenSSL REQUIRED)

add_custom_command(
  OUTPUT oecertdump_u.h oecertdump_u.c oecertdump_args.h
  DEPENDS ../oecertdump.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecertdump.edl
          --search-path ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_executable(oecertdump host.cpp sgx_quote.cpp
                          ${CMAKE_CURRENT_BINARY_DIR}/oecertdump_u.c)

target_include_directories(oecertdump PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                              -I/usr/include/openssl)

target_link_libraries(oecertdump oehost OpenSSL::SSL)

if (HAS_QUOTE_PROVIDER)
  target_compile_definitions(oecertdump PRIVATE OE_LINK_SGX_DCAP_QL)
endif ()

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, oecertdump will be compiled at w2 level.
if (WIN32)
  target_compile_options(oecertdump PRIVATE /W2)
endif ()
