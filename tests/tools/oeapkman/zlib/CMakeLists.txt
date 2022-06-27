# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# Use add_test so that we can use the < > shell redirection operators.
add_test(
  NAME tests/tools/oeapkman/zlib
  COMMAND
    ${CMAKE_COMMAND} -E env bash -c
    "host/zlib_host enc/zlib_enc -c ${PROJECT_SOURCE_DIR}/CHANGELOG.md ${CMAKE_CURRENT_BINARY_DIR}/ch.z &&\
       host/zlib_host enc/zlib_enc -d ${CMAKE_CURRENT_BINARY_DIR}/ch.z ${CMAKE_CURRENT_BINARY_DIR}/CHANGELOG_OUT.md &&\
       cmp -n 35431 ${PROJECT_SOURCE_DIR}/CHANGELOG.md CHANGELOG_OUT.md")
