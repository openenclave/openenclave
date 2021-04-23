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
  OUTPUT attestation_perf_u.h attestation_perf_u.c attestation_perf_args.h
  DEPENDS ../attestation_perf.edl edger8r
  COMMAND
    edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../attestation_perf.edl
    --search-path ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_executable(
  attestation_perf host.cpp cache.cpp
                   ${CMAKE_CURRENT_BINARY_DIR}/attestation_perf_u.c)

target_include_directories(attestation_perf PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                    -I/usr/include/openssl)

target_link_libraries(attestation_perf oehost OpenSSL::SSL)

# The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
# glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
# raises a W3 warning and triggers error C2220 (warning treated as error).
# To work around for this internal tool, attestation_perf will be compiled at w2 level.
if (WIN32)
  target_compile_options(attestation_perf PRIVATE /W2)
endif ()

# Generate the attestation_perf binary in the the same directory with enclave binary
set_target_properties(
  attestation_perf PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                              "${CMAKE_CURRENT_BINARY_DIR}/..")
