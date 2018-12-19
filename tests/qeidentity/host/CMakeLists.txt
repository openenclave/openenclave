# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tests.edl host gen)
add_executable(qeidentity_host host.cpp qeidentifyinfo.cpp ${gen})

if(USE_LIBSGX)
    target_compile_definitions(qeidentity_host PRIVATE OE_USE_LIBSGX)
endif()

add_custom_command(TARGET qeidentity_host
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data ${CMAKE_CURRENT_BINARY_DIR}/../data
)

target_include_directories(qeidentity_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(qeidentity_host oehostapp)
