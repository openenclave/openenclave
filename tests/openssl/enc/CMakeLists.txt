# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl.edl)

add_custom_command(
  OUTPUT openssl_t.h openssl_t.c openssl_args.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# Helper library for running openssl test (the libtestutil.a from openssl).
add_enclave_library(
  openssl-support
  ${OPENSSL_DIR}/test/testutil/basic_output.c
  ${OPENSSL_DIR}/test/testutil/cb.c
  ${OPENSSL_DIR}/test/testutil/driver.c
  ${OPENSSL_DIR}/test/testutil/format_output.c
  ${OPENSSL_DIR}/test/testutil/main.c
  ${OPENSSL_DIR}/test/testutil/output_helpers.c
  ${OPENSSL_DIR}/test/testutil/random.c
  ${OPENSSL_DIR}/test/testutil/stanza.c
  ${OPENSSL_DIR}/test/testutil/tap_bio.c
  ${OPENSSL_DIR}/test/testutil/test_cleanup.c
  ${OPENSSL_DIR}/test/testutil/tests.c
  ${OPENSSL_DIR}/test/testutil/testutil_init.c
  thread.cpp
  # Ensure that openssl_t.h is generated.
  openssl_t.h)

enclave_compile_options(
  openssl-support PRIVATE -Wno-shorten-64-to-32 -Wno-sign-conversion
  -Wno-conversion -Wno-unused-parameter)

enclave_link_libraries(openssl-support PRIVATE oelibcxx oelibc oe_includes)
enclave_include_directories(
  openssl-support PRIVATE ${OPENSSL_DIR}/include
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include
  ${CMAKE_CURRENT_BINARY_DIR})

# Helper library for running openssl_3 test (libtestutil.a from openssl_3).
add_enclave_library(
  openssl_3-support
  ${OPENSSL_3_DIR}/apps/lib/app_libctx.c
  ${OPENSSL_3_DIR}/apps/lib/app_params.c
  ${OPENSSL_3_DIR}/apps/lib/app_provider.c
  ${OPENSSL_3_DIR}/apps/lib/app_rand.c
  ${OPENSSL_3_DIR}/apps/lib/app_x509.c
  ${OPENSSL_3_DIR}/apps/lib/apps_ui.c
  ${OPENSSL_3_DIR}/apps/lib/columns.c
  ${OPENSSL_3_DIR}/apps/lib/engine.c
  ${OPENSSL_3_DIR}/apps/lib/engine_loader.c
  ${OPENSSL_3_DIR}/apps/lib/fmt.c
  ${OPENSSL_3_DIR}/apps/lib/http_server.c
  ${OPENSSL_3_DIR}/apps/lib/names.c
  ${OPENSSL_3_DIR}/apps/lib/opt.c
  ${OPENSSL_3_DIR}/apps/lib/s_cb.c
  ${OPENSSL_3_DIR}/apps/lib/s_socket.c
  ${OPENSSL_3_DIR}/test/testutil/basic_output.c
  ${OPENSSL_3_DIR}/test/testutil/cb.c
  ${OPENSSL_3_DIR}/test/testutil/driver.c
  ${OPENSSL_3_DIR}/test/testutil/fake_random.c
  ${OPENSSL_3_DIR}/test/testutil/format_output.c
  ${OPENSSL_3_DIR}/test/testutil/testutil_init.c
  ${OPENSSL_3_DIR}/test/testutil/load.c
  ${OPENSSL_3_DIR}/test/testutil/main.c
  ${OPENSSL_3_DIR}/test/testutil/output.c
  ${OPENSSL_3_DIR}/test/testutil/options.c
  ${OPENSSL_3_DIR}/test/testutil/provider.c
  ${OPENSSL_3_DIR}/test/testutil/random.c
  ${OPENSSL_3_DIR}/test/testutil/stanza.c
  ${OPENSSL_3_DIR}/test/testutil/test_cleanup.c
  ${OPENSSL_3_DIR}/test/testutil/test_options.c
  ${OPENSSL_3_DIR}/test/testutil/tests.c
  thread.cpp
  # Ensure that openssl_t.h is generated.
  openssl_t.h)

enclave_compile_definitions(openssl_3-support PRIVATE __STDC_NO_ATOMICS__)

enclave_compile_options(
  openssl_3-support PRIVATE -Wno-shorten-64-to-32 -Wno-sign-conversion
  -Wno-conversion -Wno-unused-parameter)

enclave_link_libraries(openssl_3-support PRIVATE oelibcxx oelibc oe_includes)
enclave_include_directories(
  openssl_3-support
  PRIVATE
  ${OPENSSL_3_DIR}
  ${OPENSSL_3_DIR}/include
  ${OPENSSL_3_DIR}/apps/include
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include_3
  ${CMAKE_CURRENT_BINARY_DIR})

# Create an object library to avoid recompiling these files.
# These cannot be added to openssl-support since they'd result in multiple
# definition errors due to the way test_cleanup.c is written.
add_enclave_library(openssl-common OBJECT enc.c
                    ${CMAKE_CURRENT_BINARY_DIR}/openssl_t.c)
add_enclave_dependencies(openssl-common openssl_generated)
enclave_compile_definitions(openssl-common PRIVATE OECRYPTO_OPENSSL_VER=1)

enclave_link_libraries(openssl-common PRIVATE oelibc oe_includes)
enclave_include_directories(
  openssl-common PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_DIR}/include
  ${OPENSSL_DIR}/test/testutil
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include)

maybe_build_using_clangw(openssl-common)

add_enclave_library(openssl_3-common OBJECT enc.c
                    ${CMAKE_CURRENT_BINARY_DIR}/openssl_t.c)
add_enclave_dependencies(openssl_3-common openssl_3_generated)
enclave_compile_definitions(openssl_3-common PRIVATE OECRYPTO_OPENSSL_VER=3)

enclave_link_libraries(openssl_3-common PRIVATE oelibc oe_includes)
enclave_include_directories(
  openssl_3-common
  PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${OPENSSL_3_DIR}/include
  ${OPENSSL_3_DIR}/apps/include
  ${OPENSSL_3_DIR}/test/testutil
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include_3)

maybe_build_using_clangw(openssl_3-common)

if (CODE_COVERAGE)
  enclave_compile_definitions(openssl-common PRIVATE CODE_COVERAGE)
  enclave_compile_definitions(openssl_3-common PRIVATE CODE_COVERAGE)
endif ()

# Add the dependency to the opensslconf.h.
add_enclave_dependencies(openssl-support openssl_generated)
add_enclave_dependencies(openssl_3-support openssl_3_generated)

if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
  # Make sure the symcrypt module is placed under the same directory as enclave
  # binaries
  add_custom_command(
    TARGET openssl-support
    COMMAND
      ${CMAKE_COMMAND} -E copy
      ${CMAKE_BINARY_DIR}/3rdparty/symcrypt_engine/SymCrypt/lib/${SYMCRYPT_NAME}
      ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRYPT_LINK_NAME})
endif ()

# List the tests that require ssltestlib.c.
set(SSL_TEST_LIST
    "asynciotest"
    "dtls_mtu_test"
    "dtlstest"
    "fatalerrtest"
    "gosttest"
    "recordlentest"
    "servername_test"
    "sslapitest"
    "sslbuffertest"
    "sslcorrupttest"
    "tls13ccstest")

# List the tests that require cmp_testlib.c.
set(CMP_TEST_LIST "cmp_msg_test" "cmp_protect_test" "cmp_server_test"
                  "cmp_vfy_test")

# Helper function to generate source file for buildtests.
function (generate_buildtest TESTNAME CRYPTO_LIB)
  if (CRYPTO_LIB STREQUAL "OpenSSL")
    set(TEST_NAME "${TESTNAME}")
    set(TEST_OPENSSL_DIR ${OPENSSL_DIR})
  elseif (CRYPTO_LIB STREQUAL "OpenSSL_3")
    set(TEST_NAME "3-${TESTNAME}")
    set(TEST_OPENSSL_DIR ${OPENSSL_3_DIR})
  else ()
    message(FATAL_ERROR "${CRYPTO_LIB} is unsupported for OpenSSL tests")
  endif ()

  set(GEN_BUILDTEST_PL ${TEST_OPENSSL_DIR}/test/generate_buildtest.pl)
  string(REPLACE "buildtest_" "" NAME "${TESTNAME}")
  add_custom_command(
    OUTPUT ${TEST_NAME}.c
    DEPENDS ${GEN_BUILDTEST_PL}
    COMMAND ${OE_PERL} ${GEN_BUILDTEST_PL} ${NAME} > ${TEST_NAME}.c)
endfunction ()

# Helper function to build source for each enclave test.
# Some tests require additional source files to be added.
function (add_openssl_test_enc NAME BUILDTEST CRYPTO_LIB)
  if (CRYPTO_LIB STREQUAL "OpenSSL")
    set(TEST_NAME "${NAME}")
    set(TEST_OPENSSL_DIR ${OPENSSL_DIR})
    set(TEST_OPENSSL_INCLUDE_DIRS
        ${OPENSSL_DIR}/include
        ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include)
  elseif (CRYPTO_LIB STREQUAL "SymCrypt_FIPS")
    set(TEST_NAME "${NAME}_symcrypt")
    set(TEST_OPENSSL_DIR ${OPENSSL_DIR})
    set(TEST_OPENSSL_INCLUDE_DIRS
        ${OPENSSL_DIR}/include
        ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include)
  elseif (CRYPTO_LIB STREQUAL "OpenSSL_3")
    set(TEST_NAME "3-${NAME}")
    set(TEST_OPENSSL_DIR ${OPENSSL_3_DIR})
    set(TEST_OPENSSL_INCLUDE_DIRS
        ${OPENSSL_3_DIR}/include
        ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include_3)
  else ()
    message(FATAL_ERROR "${CRYPTO_LIB} is unsupported for OpenSSL tests")
  endif ()

  if (BUILDTEST)
    if (CRYPTO_LIB STREQUAL "OpenSSL_3")
      list(APPEND TEST_SRC 3-${NAME}.c)
    else ()
      list(APPEND TEST_SRC ${NAME}.c)
    endif ()
  else ()
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/${NAME}.c)
  endif ()

  if ("${NAME}" IN_LIST CMP_TEST_LIST)
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/helpers/cmp_testlib.c)
  endif ()

  if ("${NAME}" IN_LIST SSL_TEST_LIST)
    if (CRYPTO_LIB STREQUAL "OpenSSL_3")
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/helpers/ssltestlib.c)
    else ()
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/ssltestlib.c)
    endif ()
  endif ()

  if ("${NAME}" STREQUAL "drbg_cavs_test")
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/drbg_cavs_data.c)
  endif ()

  if ("${NAME}" STREQUAL "endecode_test")
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/helpers/predefined_dhparams.c)
  endif ()

  if ("${NAME}" STREQUAL "pkcs12_format_test")
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/helpers/pkcs12.c)
  endif ()

  if ("${NAME}" STREQUAL "provider_pkey_test")
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/fake_rsaprov.c)
  endif ()

  if ("${NAME}" STREQUAL "provider_test" OR "${NAME}" STREQUAL
                                            "provider_internal_test")
    add_definitions(-DNO_PROVIDER_MODULE
                    -DPROVIDER_INIT_FUNCTION_NAME=p_test_init)
    list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/p_test.c)
  endif ()

  if ("${NAME}" STREQUAL "ssl_test_ctx_test")
    if ("${CRYPTO_LIB}" STREQUAL "OpenSSL_3")
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/helpers/ssl_test_ctx.c)
    else ()
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/ssl_test_ctx.c)
    endif ()
  endif ()

  if ("${NAME}" STREQUAL "ssl_test")
    if ("${CRYPTO_LIB}" STREQUAL "OpenSSL_3")
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/helpers/ssl_test_ctx.c
           ${TEST_OPENSSL_DIR}/test/helpers/handshake.c)
    else ()
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/ssl_test_ctx.c
           ${TEST_OPENSSL_DIR}/test/handshake_helper.c)
    endif ()
  endif ()

  if ("${NAME}" STREQUAL "sslapitest")
    if ("${CRYPTO_LIB}" STREQUAL "OpenSSL_3")
      list(APPEND TEST_SRC ${TEST_OPENSSL_DIR}/test/filterprov.c
           ${TEST_OPENSSL_DIR}/test/tls-provider.c)
    endif ()
    # OpenSSL 1.0 doesn't require any additional files.
  endif ()

  add_enclave(
    TARGET
    openssl-${TEST_NAME}_enc
    # Building the enclave by default when enabling LVI mitigation to
    # test linking against LVI-mitigated libraries.
    ADD_LVI_MITIGATION
    CRYPTO_LIB
    ${CRYPTO_LIB}
    SOURCES
    ${TEST_SRC})

  enclave_include_directories(
    openssl-${TEST_NAME}_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ${TEST_OPENSSL_DIR} ${TEST_OPENSSL_INCLUDE_DIRS})

  enclave_compile_options(
    openssl-${TEST_NAME}_enc
    PRIVATE
    -Wno-shorten-64-to-32
    -Wno-sign-conversion
    -Wno-conversion
    -Wno-unused-parameter
    -Wno-deprecated-declarations)

  enclave_compile_definitions(
    openssl-${TEST_NAME}_enc PRIVATE OPENSSL_NO_AFALGENG __STDC_NO_ATOMICS__
    OPENSSL_NO_RAND_DRBG)

  list(APPEND INCLUDE_PATHS ${CMAKE_CURRENT_BINARY_DIR}
       ${TEST_OPENSSL_DIR}/test ${TEST_OPENSSL_DIR}/test/testutil
       ${TEST_OPENSSL_DIR}/apps/include)

  if ("${NAME}" STREQUAL "bn_internal_test")
    list(APPEND INCLUDE_PATHS ${TEST_OPENSSL_DIR}/crypto/bn)
  endif ()

  if ("${NAME}" STREQUAL "curve448_internal_test")
    list(APPEND INCLUDE_PATHS ${TEST_OPENSSL_DIR}/crypto/ec/curve448)
  endif ()

  if ("${NAME}" STREQUAL "ec_internal_test")
    list(APPEND INCLUDE_PATHS ${TEST_OPENSSL_DIR}/crypto/ec)
  endif ()

  if ("${NAME}" STREQUAL "rsa_sp800_56b_test")
    list(APPEND INCLUDE_PATHS ${TEST_OPENSSL_DIR}/crypto/rsa)
  endif ()

  enclave_include_directories(openssl-${TEST_NAME}_enc PRIVATE ${INCLUDE_PATHS})

  if (CRYPTO_LIB STREQUAL "OpenSSL_3")
    enclave_link_libraries(openssl-${TEST_NAME}_enc openssl_3-support
                           openssl_3-common oehostsock oehostfs oehostresolver)
  else ()
    enclave_link_libraries(openssl-${TEST_NAME}_enc openssl-support
                           openssl-common oehostsock oehostfs oehostresolver)
  endif ()

  if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
    # Propagate CMAKE_SKIP_RPATH variable.
    set(CMAKE_SKIP_RPATH
        "${CMAKE_SKIP_RPATH}"
        PARENT_SCOPE)
  endif ()

  if (WIN32)
    maybe_build_using_clangw(openssl-${TEST_NAME}_enc)

    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables.
    set(CMAKE_STATIC_LIBRARY_PREFIX
        "${CMAKE_STATIC_LIBRARY_PREFIX}"
        PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX
        "${CMAKE_STATIC_LIBRARY_SUFFIX}"
        PARENT_SCOPE)

    # Propagate library tool variables.
    set(CMAKE_C_CREATE_STATIC_LIBRARY
        "${CMAKE_C_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY
        "${CMAKE_CXX_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)

    # Propagate linker variables.
    set(CMAKE_EXECUTABLE_SUFFIX
        "${CMAKE_EXECUTABLE_SUFFIX}"
        PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES
        "${CMAKE_C_STANDARD_LIBRARIES}"
        PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE
        "${CMAKE_C_LINK_EXECUTABLE}"
        PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES
        "${CMAKE_CXX_STANDARD_LIBRARIES}"
        PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE
        "${CMAKE_CXX_LINK_EXECUTABLE}"
        PARENT_SCOPE)

    # Propagate cpmpiler variables.
    set(CMAKE_C_COMPILE_OBJECT
        "${CMAKE_C_COMPILE_OBJECT}"
        PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT
        "${CMAKE_CXX_COMPILE_OBJECT}"
        PARENT_SCOPE)
  endif ()
endfunction (add_openssl_test_enc)

# Create tests for each entry in all .supported files.
file(STRINGS "../tests.supported.buildtest" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")
  generate_buildtest(${name} "OpenSSL")
  add_openssl_test_enc(${name} TRUE "OpenSSL")
  if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
    add_openssl_test_enc(${name} TRUE "SymCrypt_FIPS")
  endif ()
endforeach (testcase)

file(STRINGS "../tests.supported" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")
  add_openssl_test_enc(${name} FALSE "OpenSSL")
  if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
    add_openssl_test_enc(${name} FALSE "SymCrypt_FIPS")
  endif ()
endforeach (testcase)

file(STRINGS "../tests_3.supported.buildtest" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl_3/test/")
  generate_buildtest(${name} "OpenSSL_3")
  add_openssl_test_enc(${name} TRUE "OpenSSL_3")
  # OpenSSL_3 doesn't support symcrypt
endforeach (testcase)

file(STRINGS "../tests_3.supported" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl_3/test/")
  add_openssl_test_enc(${name} FALSE "OpenSSL_3")
  # OpenSSL_3 doesn't support symcrypt
endforeach (testcase)
