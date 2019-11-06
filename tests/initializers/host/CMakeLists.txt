# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../initializers.edl host gen)

add_executable(initializers_host host.cpp ${gen})

target_include_directories(initializers_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(initializers_host oehostapp)
