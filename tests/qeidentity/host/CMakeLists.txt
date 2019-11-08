# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../tests.edl host gen)
add_executable(qeidentity_host host.cpp qeidentifyinfo.cpp ${gen})

if(HAS_QUOTE_PROVIDER)
    target_compile_definitions(qeidentity_host PRIVATE OE_LINK_SGX_DCAP_QL)
endif()

add_custom_command(TARGET qeidentity_host
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data ${CMAKE_CURRENT_BINARY_DIR}/../data
)

target_include_directories(qeidentity_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(qeidentity_host oehostapp)
