# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(NAME tests/host_verify
         COMMAND $<TARGET_FILE:test_host_verify> ${ARGN}
         WORKING_DIRECTORY $<TARGET_FILE_DIR:test_host_verify>)

