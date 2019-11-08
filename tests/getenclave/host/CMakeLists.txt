# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../getenclave.edl host gen)

add_executable(getenclave_host host.c ${gen})
target_include_directories(getenclave_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(getenclave_host oehostapp)
