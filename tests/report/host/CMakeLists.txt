# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tests.edl host gen)
add_executable(report_host host.cpp tcbinfo.cpp ../common/tests.cpp ${gen})

if(USE_LIBSGX)
    target_compile_definitions(report_host PRIVATE OE_USE_LIBSGX)
endif()

add_custom_command(TARGET report_host
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data ${CMAKE_CURRENT_BINARY_DIR}/../data
)

target_include_directories(report_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(report_host oehostapp)
