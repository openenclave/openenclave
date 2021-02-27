# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# TODO: Figure out robust way to add test.
#add_test(NAME tests/tools/apkman/event
#         COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test.bash")
