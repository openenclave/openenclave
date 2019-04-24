# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../echod.edl host gen)

add_executable(echod_host host.c ${gen})

# Add the directory containing echod_u.h to the include path.
target_include_directories(echod_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(echod_host oehostapp)
