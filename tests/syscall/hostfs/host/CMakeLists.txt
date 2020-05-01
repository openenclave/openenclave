# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


set (EDL_FILE ../test_hostfs.edl)

add_custom_command(
    OUTPUT test_hostfs_u.h test_hostfs_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
            --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../device/edl)

add_executable(hostfs_host host.c test_hostfs_u.c)

target_include_directories(hostfs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(hostfs_host oehostapp)
target_link_libraries(hostfs_host rmdir)
