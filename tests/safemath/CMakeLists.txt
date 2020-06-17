# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(safemath main.cpp)
target_link_libraries(safemath oehost)

add_test(NAME tests/safemath COMMAND safemath)
