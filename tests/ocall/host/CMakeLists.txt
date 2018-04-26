# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ocall_host host.cpp)

target_link_libraries(ocall_host oehostapp)

target_compile_options(ocall_host PRIVATE
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-variable
    )
