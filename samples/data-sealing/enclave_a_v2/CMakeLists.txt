# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(enclave_a_v2 ecalls.cpp)

if (WIN32)
  maybe_build_using_clangw(enclave_a_v2)
endif ()

target_link_libraries(enclave_a_v2 common)
