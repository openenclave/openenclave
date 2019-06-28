# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../tests.edl enclave gen)
# TODO: Does this need CXX?
add_enclave(TARGET qeidentity_enc UUID a656f3b1-d319-4692-bcd6-a2f50d9fb1e5 SOURCES enc.cpp ${gen})

if(USE_LIBSGX)
    target_compile_definitions(qeidentity_enc PRIVATE OE_USE_LIBSGX)
endif()

target_include_directories(qeidentity_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(qeidentity_enc oelibc)
