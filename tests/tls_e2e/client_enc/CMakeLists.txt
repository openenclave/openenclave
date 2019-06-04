# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tls_e2e.edl enclave gen)

add_enclave(TARGET tls_client_enc SOURCES client.cpp tls_e2e_t.c ../common/utility.cpp ${gen})

if(USE_LIBSGX)
    target_compile_definitions(tls_client_enc PRIVATE OE_USE_LIBSGX)
endif()

set_source_files_properties(
   tls_e2e_t.c
   PROPERTIES COMPILE_FLAGS "-Wno-conversion")

target_include_directories(tls_client_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(tls_client_enc oeenclave oelibc oehostsock oehostresolver)
