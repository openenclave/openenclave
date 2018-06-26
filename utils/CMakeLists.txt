# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(utils main.c)
target_link_libraries(utils oehost)

add_test(NAME tests/utils COMMAND ./utils)