# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(UNIX)
    set(EDL_FILE "../linux/fs.edl")
else()
    set(EDL_FILE "../windows/fs.edl")
endif()

set(EDL_SEARCH_DIR "../../../../posix/devices/sgxfs")

oeedl_file(${EDL_FILE} enclave gen --edl-search-dir ${EDL_SEARCH_DIR})

add_enclave(TARGET fs_enc SOURCES enc.cpp ${gen})

target_include_directories(fs_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (TEST_SGXFS)
    target_compile_definitions(fs_enc PRIVATE TEST_SGXFS=1)
    set(OESGXFSENCLAVE oesgxfsenclave)
else
    set(OESGXFSENCLAVE "")
endif()

target_link_libraries(fs_enc
    ${OESGXFSENCLAVE} oelibcxx oecpio oeenclave oehostfs)
