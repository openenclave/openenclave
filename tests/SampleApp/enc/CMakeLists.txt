# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# TODO: Does this need CXX?

oeedl_file(../SampleApp.edl enclave gen)

add_enclave(TARGET SampleApp UUID 25419627-14f6-4625-9329-cf5f10a57fea SOURCES SampleApp.cpp ${gen})

target_include_directories(SampleApp PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleApp oelibc)
