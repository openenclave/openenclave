# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../SampleAppCRT.edl host gen)

add_executable(SampleAppCRTHost SampleAppCRTHost.cpp ${gen})

target_include_directories(SampleAppCRTHost PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleAppCRTHost oehostapp)
