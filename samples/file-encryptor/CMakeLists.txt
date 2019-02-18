# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_test(samples/file-encryptor ${CMAKE_CURRENT_BINARY_DIR}/host/file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile ${CMAKE_CURRENT_BINARY_DIR}/enc/file-encryptor_enc.signed)
set_tests_properties(samples/file-encryptor PROPERTIES SKIP_RETURN_CODE 1)
add_test(samples/file-encryptor_simulation ${CMAKE_CURRENT_BINARY_DIR}/host/file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile ${CMAKE_CURRENT_BINARY_DIR}/enc/file-encryptor_enc.signed --simulate)
