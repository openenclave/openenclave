# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ocall-restrict_host host.cpp)
target_link_libraries(ocall-restrict_host oehostapp)
