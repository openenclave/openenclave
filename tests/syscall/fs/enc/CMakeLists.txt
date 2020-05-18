# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  set(EDL_FILE "../linux/fs.edl")
else ()
  set(EDL_FILE "../windows/fs.edl")
endif ()

set(EDL_SEARCH_DIR "../../../../syscall/devices/sgxfs")

add_custom_command(
  OUTPUT fs_t.h fs_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR} --search-path ${EDL_SEARCH_DIR})

add_enclave(TARGET fs_enc SOURCES enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/fs_t.c)

enclave_include_directories(fs_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (TEST_SGXFS)
  enclave_compile_definitions(fs_enc PRIVATE TEST_SGXFS=1)
  set(OESGXFSENCLAVE oesgxfsenclave)
else ()
  set(OESGXFSENCLAVE "")
endif ()

enclave_link_libraries(fs_enc ${OESGXFSENCLAVE} oelibcxx oecpio oeenclave
                       oehostfs)
