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
  OUTPUT oeutil_u.h oeutil_u.c oeutil_args.h
  DEPENDS ../oeutil.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oeutil.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_executable(oeutil host.cpp generate_evidence.cpp
                      ${CMAKE_CURRENT_BINARY_DIR}/ oeutil_u.c)

add_dependencies(oeutil enclave_key_pair)

target_include_directories(oeutil PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                          -I/usr/include/openssl)

target_link_libraries(oeutil oehost OpenSSL::SSL)

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, oecertdump will be compiled at w2 level.
if (WIN32)
  target_compile_options(oeutil PRIVATE /W2)
endif ()

# Generate the oeutil binary in the the same directory with enclave binary
set_target_properties(oeutil PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

install(
  TARGETS oeutil
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_BINDIR})
