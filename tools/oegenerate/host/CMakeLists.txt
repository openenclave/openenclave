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
  OUTPUT oegenerate_u.h oegenerate_u.c oegenerate_args.h
  DEPENDS ../oegenerate.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oegenerate.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_executable(oegenerate host.cpp evidence.cpp
                          ${CMAKE_CURRENT_BINARY_DIR}/oegenerate_u.c)

add_dependencies(oegenerate enclave_key_pair)

target_include_directories(oegenerate PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                              -I/usr/include/openssl)

target_link_libraries(oegenerate oehost OpenSSL::SSL)

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, oecertdump will be compiled at w2 level.
if (WIN32)
  target_compile_options(oegenerate PRIVATE /W2)
endif ()

# Generate the oegenerate binary in the the same directory with enclave binary
set_target_properties(oegenerate PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                            ${OE_BINDIR})

install(
  TARGETS oegenerate
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_BINDIR})
