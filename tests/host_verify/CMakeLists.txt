# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(NAME tests/host_verify
         COMMAND $<TARGET_FILE:test_host_verify>
         WORKING_DIRECTORY $<TARGET_FILE_DIR:test_host_verify>)
set_tests_properties(tests/host_verify PROPERTIES SKIP_RETURN_CODE 2)

