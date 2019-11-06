# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if(UNIX)
    set(EDL_FILE "../linux/fs.edl")
else()
    set(EDL_FILE "../windows/fs.edl")
endif()

set(EDL_SEARCH_DIR "../../../../syscall/devices/sgxfs")

oeedl_file(${EDL_FILE} host gen --edl-search-dir ${EDL_SEARCH_DIR})

add_executable(fs_host host.c ${gen})

target_include_directories(fs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (TEST_SGXFS)
    target_compile_definitions(fs_host PRIVATE TEST_SGXFS=1)
    set(OESGXFSHOST oesgxfshost)
else()
    set(OESGXFSHOST "")
endif()

target_link_libraries(fs_host ${OESGXFSHOST} oehostapp)
