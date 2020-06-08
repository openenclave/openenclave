# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Copy all manually authored test configs to output folder
add_custom_command(
  OUTPUT valid.conf
  COMMAND cmake -E copy ${CMAKE_CURRENT_SOURCE_DIR}/valid.conf
          ${CMAKE_CURRENT_BINARY_DIR})

# Generate an empty config file
add_custom_command(
  OUTPUT empty.conf COMMAND python
                            ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py 0)

# Generate a config file with negative value
add_custom_command(
  OUTPUT negative_num_heap_pages.conf
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py 1)

add_custom_target(oesign_test_configs ALL DEPENDS valid.conf empty.conf
                                                  negative_num_heap_pages.conf)

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
