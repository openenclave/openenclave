# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if(UNIX)
    set(EDL_FILE "../linux/fs.edl")
else()
    set(EDL_FILE "../windows/fs.edl")
endif()

set(EDL_SEARCH_DIR "../../../../syscall/devices/sgxfs")

oeedl_file(${EDL_FILE} enclave gen --edl-search-dir ${EDL_SEARCH_DIR})

add_enclave(TARGET fs_enc SOURCES enc.cpp ${gen})

enclave_include_directories(fs_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (TEST_SGXFS)
    enclave_compile_definitions(fs_enc PRIVATE TEST_SGXFS=1)
    set(OESGXFSENCLAVE oesgxfsenclave)
else()
    set(OESGXFSENCLAVE "")
endif()

enclave_link_libraries(fs_enc
    ${OESGXFSENCLAVE} oelibcxx oecpio oeenclave oehostfs)
