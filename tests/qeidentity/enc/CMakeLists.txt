# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tests.edl enclave gen)
add_executable(qeidentity_enc enc.cpp ${gen})

if(USE_LIBSGX)
    target_compile_definitions(qeidentity_enc PRIVATE OE_USE_LIBSGX)
endif()    

target_include_directories(qeidentity_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(qeidentity_enc oeenclave)
