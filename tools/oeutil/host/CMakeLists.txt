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

add_executable(oeutil host.cpp generate_evidence.cpp get_endorsements.cpp
                      ${CMAKE_CURRENT_BINARY_DIR}/ oeutil_u.c)

add_dependencies(oeutil enclave_key_pair)

target_include_directories(oeutil PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                          -I/usr/include/openssl)

target_link_libraries(oeutil oehost_prerelease_test OpenSSL::SSL)

# To enable oeutil to load any public key
target_compile_definitions(oeutil PUBLIC OEUTIL_TCB_ALLOW_ANY_ROOT_KEY
                                         OEUTIL_QUOTE_BYPASS_DATE_CHECK)

if (WIN32)
  # The X509_print_ex_fp function in OpenSSL requires to include applink.c, which
  # glues OpenSSL BIO and Win32 compiler run-time. But applink.c uses fopen() that
  # raises a W3 warning and triggers error C2220 (warning treated as error).
  # To work around for this internal tool, oecertdump will be compiled at w2 level.
  target_compile_options(oeutil PRIVATE /W2)

  # OE build system uses OpenSSL installed by Git in Git/mingw64/,
  # to generate enclave keys, which also contains libcrypto*.dll. However,
  # oeutil.exe tool requires libcrypto-*-x64.dll that is provided in OpenSSL
  # installed by install-windows-prereqs.ps1 script (Issue #4009).
  # Statically link to oe_prereqs/OpenSSL/../libcrypto_static.lib to avoid
  # runtime dll loading issues.
  target_link_libraries(
    oeutil
    ${NUGET_PACKAGE_PATH}\\OpenSSL\\x64\\release\\lib\\libcrypto_static.lib)
endif ()

# Generate the oeutil binary in the the same directory with enclave binary
set_target_properties(oeutil PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

install(
  TARGETS oeutil
  EXPORT openenclave-targets
  DESTINATION ${CMAKE_INSTALL_BINDIR})
