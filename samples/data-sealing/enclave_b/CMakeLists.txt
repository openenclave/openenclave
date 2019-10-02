# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(enclave_b ecalls.cpp)

if(WIN32)
  maybe_build_using_clangw(enclave_b)
endif()

target_link_libraries(enclave_b common)
