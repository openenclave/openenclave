# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tls_e2e.edl enclave gen)

add_enclave(TARGET tls_server_enc SOURCES server.cpp tls_e2e_t.c ../common/utility.cpp ${gen})
if(HAS_QUOTE_PROVIDER)
    enclave_compile_definitions(tls_server_enc PRIVATE OE_LINK_SGX_DCAP_QL)
endif()

set_source_files_properties(
   tls_e2e_t.c
   PROPERTIES COMPILE_FLAGS "-Wno-conversion")

enclave_include_directories(tls_server_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    #    ${CMAKE_CURRENT_SOURCE_DIR})

#enclave_include_directories(tls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(tls_server_enc oeenclave oelibc oehostsock oehostresolver)
