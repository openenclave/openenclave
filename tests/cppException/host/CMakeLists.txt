# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../cppException.edl host gen)

add_executable(cppException_host host.cpp ${gen})

target_include_directories(cppException_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cppException_host oehostapp)
