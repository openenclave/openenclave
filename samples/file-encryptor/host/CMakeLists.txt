# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../fileencryptor.edl host gen)

add_executable(file-encryptor_host host.cpp ${gen})

target_include_directories(file-encryptor_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(file-encryptor_host oehostapp)

