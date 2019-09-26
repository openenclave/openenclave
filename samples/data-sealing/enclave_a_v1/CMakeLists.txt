# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(WIN32)
  include(maybe_build_using_clangw)
endif()

add_executable(enclave_a_v1 ecalls.cpp)

if(WIN32)
  maybe_build_using_clangw(enclave_a_v1)
endif()

target_link_libraries(enclave_a_v1 common)
