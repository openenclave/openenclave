# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  set(HOSTSRC "host_linux.c")
  set(EDL_FILE "../linux/fs.edl")
else ()
  set(HOSTSRC "host_win32.c")
  set(EDL_FILE "../windows/fs.edl")
endif ()

add_custom_command(
  OUTPUT fs_u.h fs_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(fs_host ${HOSTSRC} fs_u.c)

target_include_directories(fs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (TEST_SGXFS)
  target_compile_definitions(fs_host PRIVATE TEST_SGXFS=1)
  set(OESGXFSHOST oesgxfshost)
else ()
  set(OESGXFSHOST "")
endif ()

target_link_libraries(fs_host ${OESGXFSHOST} oehost)
target_link_libraries(fs_host rmdir)
