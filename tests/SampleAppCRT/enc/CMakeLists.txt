# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# TODO: Does this need CXX?

oeedl_file(../SampleAppCRT.edl enclave gen)

add_enclave(TARGET SampleAppCRT UUID 31c4ecec-b94a-432a-ab76-4df401b6ee59 SOURCES SampleAppCRT.cpp ${gen})

target_include_directories(SampleAppCRT PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleAppCRT oelibc)
