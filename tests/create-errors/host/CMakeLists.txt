# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(create_errors_host host.c)
target_link_libraries(create_errors_host oehostapp)
target_compile_options(create_errors_host PRIVATE -Wconversion -Wpointer-arith)
