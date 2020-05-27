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
  ${OPENSSL_DIR}/test/testutil/testutil_init.c)

enclave_compile_options(
  openssl-support PRIVATE -Wno-shorten-64-to-32 -Wno-sign-conversion
  -Wno-conversion -Wno-unused-parameter)

enclave_link_libraries(openssl-support PRIVATE oelibc oe_includes)
enclave_include_directories(openssl-support PRIVATE ${OPENSSL_DIR}/include
                            ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include)

# Add the dependency to the opensslconf.h.
add_enclave_dependencies(openssl-support openssl_generated)

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

function (generate_buildtest TESTNAME)
  set(GEN_BUILDTEST_PL ${OPENSSL_DIR}/test/generate_buildtest.pl)
  string(REPLACE "buildtest_" "" NAME "${TESTNAME}")
  add_custom_command(
    OUTPUT ${TESTNAME}.c
    DEPENDS ${GEN_BUILDTEST_PL}
    COMMAND ${OE_PERL} ${GEN_BUILDTEST_PL} ${NAME} > ${TESTNAME}.c)
endfunction ()

function (add_openssl_test_enc NAME BUILDTEST)
  if (BUILDTEST)
    list(APPEND TEST_SRC ${NAME}.c)
  else ()
    list(APPEND TEST_SRC ${OPENSSL_DIR}/test/${NAME}.c)
  endif ()

  if ("${NAME}" IN_LIST SSL_TEST_LIST)
    list(APPEND TEST_SRC ${OPENSSL_DIR}/test/ssltestlib.c)
  endif ()

  if ("${NAME}" STREQUAL "drbg_cavs_test")
    list(APPEND TEST_SRC ${OPENSSL_DIR}/test/drbg_cavs_data.c)
  endif ()

  if ("${NAME}" STREQUAL "ssl_test")
    list(APPEND TEST_SRC ${OPENSSL_DIR}/test/handshake_helper.c
         ${OPENSSL_DIR}/test/ssl_test_ctx.c)
  endif ()

  if ("${NAME}" STREQUAL "ssl_test_ctx_test")
    list(APPEND TEST_SRC ${OPENSSL_DIR}/test/ssl_test_ctx.c)
  endif ()

  add_enclave(
    TARGET
    openssl-${NAME}_enc
    # Building the enclave by default when enabling LVI mitigation to
    # test linking against LVI-mitigated libraries.
    ADD_LVI_MITIGATION
    SOURCES
    ${TEST_SRC}
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/openssl_t.c)

  enclave_include_directories(
    openssl-${NAME}_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_DIR}
    ${OPENSSL_DIR}/include ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include)

  enclave_compile_options(
    openssl-${NAME}_enc PRIVATE -Wno-shorten-64-to-32 -Wno-sign-conversion
    -Wno-conversion -Wno-unused-parameter)

  enclave_compile_definitions(openssl-${NAME}_enc PRIVATE OPENSSL_NO_AFALGENG
                              __STDC_NO_ATOMICS__)

  if (CODE_COVERAGE)
    enclave_compile_definitions(openssl-${NAME}_enc PRIVATE CODE_COVERAGE)
  endif ()

  list(APPEND INCLUDE_PATHS ${CMAKE_CURRENT_BINARY_DIR}
       ${OPENSSL_DIR}/test/testutil)

  if ("${NAME}" STREQUAL "curve448_internal_test")
    list(APPEND INCLUDE_PATHS ${OPENSSL_DIR}/crypto/ec/curve448)
  endif ()

  if ("${NAME}" STREQUAL "ec_internal_test")
    list(APPEND INCLUDE_PATHS ${OPENSSL_DIR}/crypto/ec)
  endif ()

  enclave_include_directories(openssl-${NAME}_enc PRIVATE ${INCLUDE_PATHS})

  enclave_link_libraries(
    openssl-${NAME}_enc
    openssl-support
    openssl
    oelibc
    oehostsock
    oehostfs
    oehostresolver)

  if (WIN32)
    maybe_build_using_clangw(openssl-${NAME}_enc)

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

file(STRINGS "../tests.supported.buildtest" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")
  generate_buildtest(${name})
  add_openssl_test_enc(${name} TRUE)
endforeach (testcase)

file(STRINGS "../tests.supported" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")
  add_openssl_test_enc(${name} FALSE)
endforeach (testcase)
