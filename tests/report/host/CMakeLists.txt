# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(reporthost host.cpp)
target_link_libraries(reporthost oehostapp)

#add_test(NAME tests/report COMMAND ./report)
#set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)
