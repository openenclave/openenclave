# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)

add_subdirectory(host)
if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

macro (copy_test_data OLD_FILE NEW_FILE)
  if (UNIX)
    add_custom_command(OUTPUT ${NEW_FILE} COMMAND ${CMAKE_COMMAND} -E copy
                                                  ${OLD_FILE} ${NEW_FILE})
  else ()
    # On Windows, invoking the dos2unix utility from git to replace
    # CRLF by LF in the test file.
    add_custom_command(OUTPUT ${NEW_FILE} COMMAND ${OE_DOS2UNIX} -n ${OLD_FILE}
                                                  ${NEW_FILE})
  endif ()

  # Add the copied files to the list so that the custom target
  # openssl_test_data can take dependency on.
  list(APPEND test_data_list ${NEW_FILE})
endmacro (copy_test_data)

# Copy the following test data from the OpenSSL repository so that we can enforce
# LF on Windows.

# The following files are required by the evp_test, which uses the file parsing
# APIs provided by the testutil library (i.e., see stanza.c for detail). The
# parsing API (test_readstanza) has a special logic to handle a blank line and
# assumes it ends with only `\n` (LF). Therefore, the API fails when the blank
# line ends with `\r\n` (CRLF).
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_kdf_tls1_prf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_kdf_tls1_prf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_x942_des.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_x942_des.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpencod.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpencod.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_rsa_common.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_rsa_common.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_ocb.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_ocb.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_rc2.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_rc2.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_sha.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_sha.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmac_common.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmac_common.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_kdf_hkdf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_kdf_hkdf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_krb5.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_krb5.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_scrypt.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_scrypt.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_ecdh.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_ecdh.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_sm4.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_sm4.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_mismatch.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_mismatch.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_sm3.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_sm3.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppbe_pkcs12.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppbe_pkcs12.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_md.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_md.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_tls13_kdf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_tls13_kdf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_wrap.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_wrap.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppbe_scrypt.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppbe_scrypt.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_cast5.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_cast5.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_rc5.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_rc5.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_chacha.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_chacha.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_ssh.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_ssh.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_camellia.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_camellia.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_ecx.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_ecx.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_dh.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_dh.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_whirlpool.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_whirlpool.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_sm2.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_sm2.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_blake.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_blake.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_rc4_stitched.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_rc4_stitched.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_seed.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_seed.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_rsa.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_rsa.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_cts.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_cts.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_common.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_common.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evprand.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evprand.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmac_blake.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmac_blake.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_ccm_cavs.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_ccm_cavs.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_brainpool.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_brainpool.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppbe_pbkdf2.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppbe_pbkdf2.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmac_poly1305.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmac_poly1305.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmac_siphash.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmac_siphash.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_idea.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_idea.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_siv.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_siv.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_camellia_cts.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_camellia_cts.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_bf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_bf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_dsa.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_dsa.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_x963.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_x963.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_rc4.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_rc4.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_tls12_prf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_tls12_prf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_ss.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_ss.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_x942.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_x942.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_ffdhe.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_ffdhe.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_pbkdf2.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_pbkdf2.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_pbkdf1.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_pbkdf1.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_ecdsa.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_ecdsa.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_des3_common.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_des3_common.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_kdf_scrypt.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_kdf_scrypt.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_kas.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_kas.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_tls11_prf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_tls11_prf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpkdf_hkdf.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpkdf_hkdf.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmac_cmac_des.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmac_cmac_des.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aes_stitched.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aes_stitched.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_ripemd.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_ripemd.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpmd_mdc2.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpmd_mdc2.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evppkey_ecc.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evppkey_ecc.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_des.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_des.txt)
copy_test_data(${OPENSSL_DIR}/test/recipes/30-test_evp_data/evpciph_aria.txt
               ${CMAKE_CURRENT_BINARY_DIR}/30-test_evp_data/evpciph_aria.txt)

# The following files are required by the ct_test. The test compares the in-memory
# string generated by the X509V3_EXT_print and SCT_LIST_print APIs against the
# content of the *.sct files. Given these APIs use `\n` (LF) as an end-of-line (EOL)
# by default, the comparison fails if the content of the file ends with `\r\n` (CRLF).
# Note that the EOL of the *.pem files does not affect the test results. However,
# because the test uses a same path to retrieve *.sct and *.pem files, we copy the *.pem
# files as well.
copy_test_data(${OPENSSL_DIR}/test/certs/bad.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/bad.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/ca-cert.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/ca-cert.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/ee-cert.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/ee-cert.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/embeddedSCTs1.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/embeddedSCTs1.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/embeddedSCTs1.sct
               ${CMAKE_CURRENT_BINARY_DIR}/certs/embeddedSCTs1.sct)
copy_test_data(${OPENSSL_DIR}/test/certs/embeddedSCTs1_issuer.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/embeddedSCTs1_issuer.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/embeddedSCTs3.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/embeddedSCTs3.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/embeddedSCTs3.sct
               ${CMAKE_CURRENT_BINARY_DIR}/certs/embeddedSCTs3.sct)
copy_test_data(${OPENSSL_DIR}/test/certs/embeddedSCTs3_issuer.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/embeddedSCTs3_issuer.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/leaf.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/leaf.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/rootCA.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/rootCA.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/roots.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/roots.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/sroot-cert.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/sroot-cert.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/subinterCA.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/subinterCA.pem)
copy_test_data(${OPENSSL_DIR}/test/certs/untrusted.pem
               ${CMAKE_CURRENT_BINARY_DIR}/certs/untrusted.pem)
copy_test_data(${OPENSSL_DIR}/test/ct/tls1.sct
               ${CMAKE_CURRENT_BINARY_DIR}/ct/tls1.sct)

# Add a custom target that ensures the test files are copied at build time.
add_custom_target(openssl_test_data ALL DEPENDS ${test_data_list})

# The paths to the arguments used by the tests.
set(OPENSSL_APPS_DIR ${OPENSSL_DIR}/apps)
set(OPENSSL_TEST_DIR ${OPENSSL_DIR}/test)
set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
if (WIN32)
  # Convert the "C:/" to "C/" so that the path can be used by hostfs on Windows.
  string(REPLACE ":" "" OPENSSL_APPS_DIR "${OPENSSL_APPS_DIR}")
  string(REPLACE ":" "" OPENSSL_TEST_DIR "${OPENSSL_TEST_DIR}")
  string(REPLACE ":" "" TEST_DATA_DIR "${TEST_DATA_DIR}")
endif ()

# Add buildtests.
file(STRINGS "tests.supported.buildtest" buildtests)
foreach (testcase ${buildtests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")
  add_enclave_test(tests/openssl/${name} openssl_host openssl-${name}_enc
                   ${name})
  if ((NOT "${name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
      AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
    add_enclave_test(tests/openssl/${name}_symcrypt openssl_host
                     openssl-${name}_symcrypt_enc ${name})
  endif ()
endforeach (testcase)

file(STRINGS "tests.unsupported.symcrypt" UNSUPPORTED_SYMCRYPT_TESTS)

# Helper for adding tests with arguments.
macro (add_openssl_test TEST_NAME NAME)
  add_enclave_test(tests/openssl/${TEST_NAME} openssl_host openssl-${NAME}_enc
                   ${TEST_NAME} ${ARGN})
  if ((NOT "${TEST_NAME}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
      AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
    add_enclave_test(tests/openssl/${TEST_NAME}_symcrypt openssl_host
                     openssl-${NAME}_symcrypt_enc ${TEST_NAME} ${ARGN})
  endif ()
endmacro (add_openssl_test)

# Add the rest of the tests.
file(STRINGS "tests.supported" openssltests)
foreach (testcase ${openssltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")

  if ("${name}" STREQUAL asynciotest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL clienthellotest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/session.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL cmsapitest)
    add_openssl_test(
      "${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/servercert.pem
      ${OPENSSL_TEST_DIR}/certs/serverkey.pem)
    continue()
  endif ()

  # The following tests fail with DEBUG_MALLOC because of the use of setenv.
  if ("${name}" STREQUAL conf_include_test)
    if (NOT USE_DEBUG_MALLOC)
      add_openssl_test(
        "${name}-includes" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes.cnf)
      add_openssl_test(
        "${name}-includes-file" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-file.cnf)
      add_openssl_test(
        "${name}-includes-eq" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-eq.cnf)
      add_openssl_test(
        "${name}-includes-eq-ws" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-eq-ws.cnf)
      add_openssl_test(
        "${name}-includes-broken" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-broken.cnf
        "f")
    endif ()
    continue()
  endif ()

  if ("${name}" STREQUAL ct_test)
    add_openssl_test("${name}" "${name}")
    set_enclave_tests_properties(
      tests/openssl/${name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;CT_DIR=${TEST_DATA_DIR}/ct;CERTS_DIR=${TEST_DATA_DIR}/certs"
    )
    if ((NOT "${name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;CT_DIR=${TEST_DATA_DIR}/ct;CERTS_DIR=${TEST_DATA_DIR}/certs"
      )
    endif ()

    continue()
  endif ()

  if ("${name}" STREQUAL d2i_test)
    add_openssl_test("${name}-bad_cert" "${name}" "X509" "decode"
                     ${OPENSSL_TEST_DIR}/d2i-tests/bad_cert.der)
    add_openssl_test("${name}-bad_generalname" "${name}" "GENERAL_NAME"
                     "decode" ${OPENSSL_TEST_DIR}/d2i-tests/bad_generalname.der)
    add_openssl_test("${name}-bad_bio" "${name}" "ASN1_ANY" "BIO"
                     ${OPENSSL_TEST_DIR}/d2i-tests/bad_bio.der)
    add_openssl_test("${name}-high_tag" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/high_tag.der)
    add_openssl_test("${name}-high_tag_integer" "${name}" "ASN1_INTEGER"
                     "decode" ${OPENSSL_TEST_DIR}/d2i-tests/high_tag.der)
    add_openssl_test("${name}-int0" "${name}" "ASN1_INTEGER" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int0.der)
    add_openssl_test("${name}-int1" "${name}" "ASN1_INTEGER" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int1.der)
    add_openssl_test("${name}-intminus1" "${name}" "ASN1_INTEGER" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/intminus1.der)
    add_openssl_test("${name}-int0-any" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int0.der)
    add_openssl_test("${name}-int1-any" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int1.der)
    add_openssl_test("${name}-intminus1-any" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/intminus1.der)
    add_openssl_test("${name}-bad-int-pad0" "${name}" "ASN1_INTEGER" "decode"
                     ${OPENSSL_TEST_DIR}/d2i-tests/bad-int-pad0.der)
    add_openssl_test(
      "${name}-bad-int-padminus1" "${name}" "ASN1_INTEGER" "decode"
      ${OPENSSL_TEST_DIR}/d2i-tests/bad-int-padminus1.der)
    continue()
  endif ()

  if ("${name}" STREQUAL danetest)
    add_openssl_test(
      "${name}" "${name}" "example.com" ${OPENSSL_TEST_DIR}/danetest.pem
      ${OPENSSL_TEST_DIR}/danetest.in)
    continue()
  endif ()

  if ("${name}" STREQUAL dtlstest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ectest)
    add_openssl_test("${name}" "${name}")
    continue()
  endif ()

  if ("${name}" STREQUAL evp_test)
    add_openssl_test("${name}-evpciph" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpciph.txt)
    add_openssl_test("${name}-evpdigest" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpdigest.txt)
    add_openssl_test("${name}-evpencod" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpencod.txt)
    add_openssl_test("${name}-evpmac" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpmac.txt)
    add_openssl_test("${name}-evpcase" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpcase.txt)
    add_openssl_test("${name}-evpccmcavs" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpccmcavs.txt)
    # The following two tests require sufficient heap memory (e.g., 6144 pages).
    add_openssl_test("${name}-evpkdf" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpkdf.txt)
    add_openssl_test("${name}-evppbe" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evppbe.txt)
    # This test requires sufficient heap memory (e.g., 6144 pages) with DEBUG MALLOC.
    add_openssl_test("${name}-evppkey" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evppkey.txt)
    # This test requires sufficient heap memory (e.g., 2048 pages) with DEBUG MALLOC.
    add_openssl_test("${name}-evppkey_ecc" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evppkey_ecc.txt)
    continue()
  endif ()

  if ("${name}" STREQUAL fatalerrtest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ocspapitest)
    add_openssl_test(
      "${name}" "${name}"
      ${OPENSSL_TEST_DIR}/recipes/80-test_ocsp_data/cert.pem
      ${OPENSSL_TEST_DIR}/recipes/80-test_ocsp_data/key.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL recordlentest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL servername_test)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ssl_test)
    set(subtest_name "${name}-simple")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/01-simple.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-client_auth")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/04-client_auth.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-sni")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/05-sni.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-dtls_resumption")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/11-dtls_resumption.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-dtls-certstatus")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/16-dtls-certstatus.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-renegotiate")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/17-renegotiate.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-dtls-renegotiate")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/18-dtls-renegotiate.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-mac-then-encrypt")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/19-mac-then-encrypt.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-ticket-appdata")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/27-ticket-appdata.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-seclevel")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/28-seclevel.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    # Test following tests require sufficient heap memory (e.g., 6144 pages) with DEBUG MALLOC.
    set(subtest_name "${name}-protocol-version")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/02-protocol-version.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    # Test following tests require sufficient heap memory (e.g., 2048 pages) with DEBUG MALLOC.
    set(subtest_name "${name}-dtls-protocol-version")
    add_openssl_test(
      "${subtest_name}" "${name}"
      ${OPENSSL_TEST_DIR}/ssl-tests/07-dtls-protocol-version.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-resumption")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/10-resumption.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    set(subtest_name "${name}-cert-select")
    add_openssl_test("${subtest_name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/20-cert-select.conf)
    set_enclave_tests_properties(
      tests/openssl/${subtest_name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    if ((NOT "${subtest_name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${subtest_name}_symcrypt
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()

    continue()
  endif ()

  if ("${name}" STREQUAL ssl_test_ctx_test)
    add_openssl_test("${name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl_test_ctx_test.conf)
    continue()
  endif ()

  if ("${name}" STREQUAL sslapitest)
    add_openssl_test(
      "${name}" "${name}" ${OPENSSL_TEST_DIR}/certs
      ${OPENSSL_TEST_DIR}/recipes/90-test_sslapi_data/passwd.txt
      ${TEST_DATA_DIR}/tmpfile)
    continue()
  endif ()

  if ("${name}" STREQUAL sslbuffertest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL sslcorrupttest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL sysdefaulttest)
    add_openssl_test("${name}" "${name}")
    set_enclave_tests_properties(
      tests/openssl/${name} PROPERTIES ENVIRONMENT
      OPENSSL_CONF=${OPENSSL_TEST_DIR}/sysdefault.cnf)
    if ((NOT "${name}" IN_LIST UNSUPPORTED_SYMCRYPT_TESTS)
        AND (ENABLE_SYMCRYPT_OPENSSL_TESTS))
      set_enclave_tests_properties(
        tests/openssl/${name}_symcrypt PROPERTIES ENVIRONMENT
        OPENSSL_CONF=${OPENSSL_TEST_DIR}/sysdefault.cnf)
    endif ()

    continue()
  endif ()

  if ("${name}" STREQUAL tls13ccstest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL v3ext)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/pathlen.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL verify_extra_test)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/)
    continue()
  endif ()

  if ("${name}" STREQUAL x509_check_cert_pkey_test)
    add_openssl_test(
      "${name}-rsa-cert" "${name}" ${OPENSSL_TEST_DIR}/certs/servercert.pem
      ${OPENSSL_TEST_DIR}/certs/serverkey.pem "cert" "ok")
    add_openssl_test(
      "${name}-mismatched-rsa-cert" "${name}"
      ${OPENSSL_TEST_DIR}/certs/servercert.pem
      ${OPENSSL_TEST_DIR}/certs/wrongkey.pem "cert" "failed")
    add_openssl_test(
      "${name}-dsa-cert" "${name}"
      ${OPENSSL_TEST_DIR}/certs/server-dsa-cert.pem
      ${OPENSSL_TEST_DIR}/certs/server-dsa-key.pem "cert" "ok")
    add_openssl_test(
      "${name}-ec-cert" "${name}"
      ${OPENSSL_TEST_DIR}/certs/server-ecdsa-cert.pem
      ${OPENSSL_TEST_DIR}/certs/server-ecdsa-key.pem "cert" "ok")
    add_openssl_test(
      "${name}-rsa-req" "${name}" ${OPENSSL_TEST_DIR}/certs/x509-check.csr
      ${OPENSSL_TEST_DIR}/certs/x509-check-key.pem "req" "ok")
    add_openssl_test(
      "${name}-mismatched-rsa-req" "${name}"
      ${OPENSSL_TEST_DIR}/certs/x509-check.csr
      ${OPENSSL_TEST_DIR}/certs/wrongkey.pem "req" "failed")
    continue()
  endif ()

  if ("${name}" STREQUAL x509_dup_cert_test)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/roots.pem
                     ${OPENSSL_TEST_DIR}/certs/leaf.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL x509aux)
    add_openssl_test(
      "${name}"
      "${name}"
      ${OPENSSL_TEST_DIR}/certs/roots.pem
      ${OPENSSL_TEST_DIR}/certs/root+anyEKU.pem
      ${OPENSSL_TEST_DIR}/certs/root-anyEKU.pem
      ${OPENSSL_TEST_DIR}/certs/root-cert.pem
      ${OPENSSL_TEST_DIR}/certs/invalid-cert.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ec_internal_test)
    # Disable for code coverage
    # As this test would write code coverage data to incorrect directory
    if (CODE_COVERAGE)
      continue()
    endif ()

    if (WIN32)
      add_openssl_test("${name}" "${name}" ${TEST_DATA_DIR} ${WIN32})
    else ()
      add_openssl_test("${name}" "${name}" ${TEST_DATA_DIR})
    endif ()
    continue()
  endif ()

  add_openssl_test("${name}" "${name}")
endforeach (testcase)
