# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(safecrt main.c)
target_link_libraries(safecrt oehost)

add_test(NAME tests/safecrt COMMAND ./safecrt)
