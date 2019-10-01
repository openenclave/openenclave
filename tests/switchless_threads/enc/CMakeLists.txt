# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../switchless_threads.edl enclave gen)

add_enclave(TARGET switchless_threads_enc UUID 6e818629-0ce7-46cd-822a-6c7e081fc68b SOURCES enc.c ${gen})

target_include_directories(switchless_threads_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_threads_enc oelibc)
