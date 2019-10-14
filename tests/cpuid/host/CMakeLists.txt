# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../cpuid.edl host gen)

add_executable(cpuid_host host.c ${gen})

target_include_directories(cpuid_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cpuid_host oehostapp)
