# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# TODO: Does this need CXX?

oeedl_file(../SampleApp.edl enclave gen)

add_enclave(TARGET SampleApp SOURCES SampleApp.cpp ${gen})

target_include_directories(SampleApp PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleApp oelibc)
