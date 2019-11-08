# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../test_ids.edl host gen --edl-search-dir ../../../device/edl)

add_executable(ids_host host.c ${gen})

target_include_directories(ids_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ids_host oehostapp)
