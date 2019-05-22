# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.



oeedl_file(../hostcalls.edl enclave gen)

# TODO: Does this need CXX?
add_enclave(TARGET hostcalls_enc UUID 60814a64-61e9-4fd9-9159-e158d73f6a2e SOURCES enc.cpp ${gen})

target_include_directories(hostcalls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hostcalls_enc oelibc)
