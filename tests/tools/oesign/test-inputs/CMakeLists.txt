# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Generate test variations from a standard baseline configuration
# TODO: Any test configurations that consist of more than just manipulations
# of the standard configuration values (e.g. syntax error tests) should be
# added to the test-inputs source folder and copied to the binary output
# folder on build.

add_custom_command(
  OUTPUT valid.conf
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file valid.conf)

add_custom_command(
  OUTPUT negative_num_heap_pages.conf
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file negative_num_heap_pages.conf --num_heap_pages -3)

# Generate empty config file
add_custom_command(
  OUTPUT empty.conf COMMAND cmake -E touch
                            ${CMAKE_CURRENT_BINARY_DIR}/empty.conf)

add_custom_target(oesign_test_configs ALL
                  DEPENDS empty.conf negative_num_heap_pages.conf valid.conf)

# Generate a valid SGX signing key-pair
add_custom_command(
  OUTPUT sign_key.private.pem sign_key.public.pem
  COMMAND openssl genrsa -out sign_key.private.pem -3 3072
  COMMAND openssl rsa -in sign_key.private.pem -pubout -out sign_key.public.pem)

# Generate an RSA key-pair with invalid exponent for SGX signing
add_custom_command(
  OUTPUT bad_exp_key.private.pem bad_exp_key.public.pem
  COMMAND openssl genrsa -out bad_exp_key.private.pem 3072
  COMMAND openssl rsa -in bad_exp_key.private.pem -pubout -out
          bad_exp_key.public.pem)

add_custom_target(
  oesign_test_keys ALL DEPENDS sign_key.private.pem sign_key.public.pem
                               bad_exp_key.private.pem bad_exp_key.public.pem)
