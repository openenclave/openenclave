# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mbed.edl host gen)

add_executable(libmbedtest_host host.c ocalls.c ${gen})

target_compile_definitions(libmbedtest_host PRIVATE PROJECT_DIR="${CMAKE_SOURCE_DIR}/")
if (NOT WIN32)
    target_compile_options(libmbedtest_host PRIVATE -Wno-error)
endif()

target_include_directories(libmbedtest_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(libmbedtest_host oehostapp)
