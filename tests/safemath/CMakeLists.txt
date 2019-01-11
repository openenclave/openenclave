# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(safemath main.cpp)
target_link_libraries(safemath oehost)

add_test(NAME tests/safemath COMMAND safemath)
