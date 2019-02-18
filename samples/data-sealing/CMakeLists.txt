# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc1)
  add_subdirectory(enc2)
  add_subdirectory(enc3)
endif ()

add_test(samples/data-sealing ${CMAKE_CURRENT_BINARY_DIR}/host/data-sealing_host ${CMAKE_CURRENT_BINARY_DIR}/enc1/data-sealing_enc1.signed ${CMAKE_CURRENT_BINARY_DIR}/enc2/data-sealing_enc2.signed
         ${CMAKE_CURRENT_BINARY_DIR}/enc3/data-sealing_enc3.signed)
set_tests_properties(samples/data-sealing PROPERTIES SKIP_RETURN_CODE 1)
