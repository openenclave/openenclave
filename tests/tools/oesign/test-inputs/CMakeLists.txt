# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Copy hand authored test configurations to output
#
# Any test configurations that consist of more than just manipulations
# of the standard configuration values (e.g. syntax error tests) should be
# added to the test-inputs source folder and copied to the binary output
# folder on build.
add_custom_command(
  OUTPUT duplicate_debug.conf
         duplicate_num_heap_pages.conf
         duplicate_num_stack_pages.conf
         duplicate_num_tcs.conf
         duplicate_product_id.conf
         duplicate_security_version.conf
         lowercase_debug_property.conf
  COMMAND cmake -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}
          ${CMAKE_CURRENT_BINARY_DIR})

# Generate test variations from a standard baseline configuration
add_custom_command(
  OUTPUT valid.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file valid.conf)

add_custom_command(
  OUTPUT negative_num_heap_pages.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file negative_num_heap_pages.conf --num_heap_pages -3)

# Generate variant valid configurations
add_custom_command(
  OUTPUT non_debug.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file non_debug.conf --debug 0)

add_custom_command(
  OUTPUT debug_out_of_range.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file debug_out_of_range.conf --debug 333)

add_custom_command(
  OUTPUT more_num_heap_pages.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file more_num_heap_pages.conf --num_heap_pages 2048)

add_custom_command(
  OUTPUT more_num_stack_pages.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file more_num_stack_pages.conf --num_stack_pages 2048)

add_custom_command(
  OUTPUT more_num_tcs.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file more_num_tcs.conf --num_tcs 4)

add_custom_command(
  OUTPUT new_product_id.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file new_product_id.conf --product_id 2)

add_custom_command(
  OUTPUT new_security_version.conf
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/make-oesign-config.py
          --config_file new_security_version.conf --security_version 2)

# Generate empty config file
add_custom_command(
  OUTPUT empty.conf COMMAND cmake -E touch
                            ${CMAKE_CURRENT_BINARY_DIR}/empty.conf)

add_custom_target(
  oesign_test_configs ALL
  DEPENDS duplicate_debug.conf
          duplicate_num_heap_pages.conf
          duplicate_num_stack_pages.conf
          duplicate_num_tcs.conf
          duplicate_product_id.conf
          duplicate_security_version.conf
          lowercase_debug_property.conf
          debug_out_of_range.conf
          empty.conf
          more_num_heap_pages.conf
          more_num_stack_pages.conf
          more_num_tcs.conf
          new_product_id.conf
          new_security_version.conf
          negative_num_heap_pages.conf
          non_debug.conf
          valid.conf)

# Generate a valid SGX signing key-pair and signing certificate
add_custom_command(
  OUTPUT sign_key.private.pem sign_key.cert.pem
  COMMAND openssl genrsa -out sign_key.private.pem -3 3072
  COMMAND
    openssl req -new -x509 -key sign_key.private.pem -out sign_key.cert.pem
    -outform PEM -days 31 -subj
    "/C=US/ST=Washington/L=Redmond/O=Open Enclave/CN=Self-signed Test Enclave Signer"
)

# Generate an alternative valid SGX signing key-pair and signing certificate
add_custom_command(
  OUTPUT sign_key_2.private.pem sign_key_2.cert.pem
  COMMAND openssl genrsa -out sign_key_2.private.pem -3 3072
  COMMAND
    openssl req -new -x509 -key sign_key_2.private.pem -out sign_key_2.cert.pem
    -outform PEM -days 31 -subj
    "/C=US/ST=Washington/L=Redmond/O=Open Enclave/CN=Self-signed Test Enclave Signer"
)

# Generate an RSA key-pair with invalid exponent for SGX signing
add_custom_command(OUTPUT bad_exp_key.private.pem
                   COMMAND openssl genrsa -out bad_exp_key.private.pem 3072)

add_custom_target(
  oesign_test_keys ALL
  DEPENDS sign_key.private.pem sign_key.cert.pem sign_key_2.private.pem
          sign_key_2.cert.pem bad_exp_key.private.pem)
