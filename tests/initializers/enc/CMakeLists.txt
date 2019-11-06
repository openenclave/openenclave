# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../initializers.edl enclave gen)

add_enclave(TARGET initializers_enc UUID 62f73b00-bdfe-4763-a06a-dc561a3a34d8 SOURCES enc.c ${gen})

target_include_directories(initializers_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(initializers_enc oelibc)
