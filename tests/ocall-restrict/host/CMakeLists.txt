# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ocall-restrict-host host.cpp)
target_link_libraries(ocall-restrict-host oehostapp)
