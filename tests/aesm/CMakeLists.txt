# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(aesm main.cpp)
target_link_libraries(aesm oehost)
add_test(NAME tests/aesm COMMAND ./aesm)
set_tests_properties(tests/aesm PROPERTIES SKIP_RETURN_CODE 2)

