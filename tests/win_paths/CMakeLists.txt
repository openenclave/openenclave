# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)
add_test(NAME tests/win_paths
         COMMAND $<TARGET_FILE:test_win_paths>
         WORKING_DIRECTORY $<TARGET_FILE_DIR:test_win_paths>)
set_tests_properties(tests/win_paths PROPERTIES SKIP_RETURN_CODE 2)
