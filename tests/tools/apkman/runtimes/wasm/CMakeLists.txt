# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_test(NAME tests/tools/apkman/wasm
         COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test.sh)
