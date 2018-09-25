# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(CMAKE_CXX_STANDARD 14)
add_executable(abortStatus_host host.cpp)
target_link_libraries(abortStatus_host oehostapp)
