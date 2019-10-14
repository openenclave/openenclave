# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../cpuid.edl enclave gen)

add_enclave(TARGET cpuid_enc UUID 71b0822f-42a3-4543-a97c-ca491f76b82c SOURCES enc.c ${gen})

target_include_directories(cpuid_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(cpuid_enc oelibc)
