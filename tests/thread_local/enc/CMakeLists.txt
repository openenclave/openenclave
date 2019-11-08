# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../thread_local.edl enclave gen)

# Build enclave without exported thread-locals.
add_enclave(TARGET thread_local_enc UUID 0eee03ee-0f93-4c24-8da7-6d00176c8e78 CXX SOURCES enc.cpp externs.cpp ${gen})

target_include_directories(thread_local_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Build enclave with exported thread-locals.
add_enclave(TARGET thread_local_enc_exported UUID 6dd12df2-ba89-4718-b7f4-1be7845c33e8 CXX SOURCES enc.cpp externs.cpp ${gen})

target_compile_definitions(thread_local_enc_exported PRIVATE -DEXPORT_THREAD_LOCALS=1)

target_include_directories(thread_local_enc_exported PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
