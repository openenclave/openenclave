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
  OUTPUT ${PROJ}_u.h ${PROJ}_u.c ${PROJ}_args.h
  DEPENDS ../${PROJ}.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../${PROJ}.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_executable(${PROJ} host.cpp ${CMAKE_CURRENT_BINARY_DIR}/${PROJ}_u.c)

add_dependencies(${PROJ} ${PROJ}_enclave_key_pair)

target_include_directories(${PROJ} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                           -I/usr/include/openssl)

target_link_libraries(${PROJ} oehost OpenSSL::SSL)

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, project will be compiled at w2 level.
if (WIN32)
  target_compile_options(${PROJ} PRIVATE /W2)
endif ()

# Generate the oecert binary in the the same directory with enclave binary
set_target_properties(${PROJ} PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                         "${CMAKE_CURRENT_BINARY_DIR}/..")
