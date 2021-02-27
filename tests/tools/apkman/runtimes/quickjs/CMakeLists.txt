# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(
  tests/tools/apkman/quickjs quickjs_host quickjs_enc
  ${CMAKE_CURRENT_SOURCE_DIR}/scripts/sierpinski.js
  ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tree.js)
