# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(enclavelibc_host host.c)
target_link_libraries(enclavelibc_host oehostapp)
