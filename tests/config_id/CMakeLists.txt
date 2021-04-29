# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/config_id_unsigned_no_kss_flags config_id_host
                 config_id_enc_unsigned no_kss_flags)
add_enclave_test(tests/config_id_unsigned_with_kss_flags config_id_host
                 config_id_kss_enc_unsigned with_kss_flags)
add_enclave_test(tests/config_id_signed_no_kss_flags config_id_host
                 config_id_enc_signed no_kss_flags)
add_enclave_test(tests/config_id_kss_signed_with_kss_flags config_id_host
                 config_id_kss_enc_signed with_kss_flags)
add_enclave_test(tests/config_id_signed_no_kss_conf_flags config_id_host
                 config_id_no_kss_conf_enc_signed no_kss_flags)
