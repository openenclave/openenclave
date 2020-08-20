# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(image)

set(ENCLAVE "./enc/split_enc:./image/image")

set(SIGNED_ENCLAVE "./enc/split_enc.signed:./image/image")

add_test(
  tests/split1
  ${CMAKE_BINARY_DIR}/output/bin/oesign
  sign
  -e
  ${ENCLAVE}
  -c
  ${CMAKE_CURRENT_SOURCE_DIR}/sign.conf
  -k
  ${CMAKE_CURRENT_SOURCE_DIR}/key.pem)

add_test(tests/split2 ./host/split_host ${ENCLAVE})

add_test(tests/split3 ./host/split_host ${SIGNED_ENCLAVE})
