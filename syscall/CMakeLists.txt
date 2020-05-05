# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## These rules generate the edge routines for the SYSCALL interface, which is
## installed by oe_register_syscall_ecall_function_table().
##
##==============================================================================

set(OE_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(EDL_DIR ${CMAKE_SOURCE_DIR}/include/openenclave/edl)
set(EDL_FILE ${EDL_DIR}/syscall.edl)
if (COMPILE_SYSTEM_EDL)
  add_custom_command(
    OUTPUT syscall_t.h syscall_t.c syscall_args.h
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --search-path ${OE_INCLUDE_DIR} --trusted ${EDL_FILE})

  add_custom_target(syscall_trusted_edl DEPENDS syscall_t.h syscall_t.c
                                                syscall_args.h)

  list(APPEND SOURCES syscall_t_wrapper.c)
else ()
  # Generate headers only
  add_custom_command(
    OUTPUT syscall_t.h syscall_args.h
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --header-only --search-path ${OE_INCLUDE_DIR} --trusted
            ${EDL_FILE})

  add_custom_target(syscall_trusted_edl DEPENDS syscall_t.h syscall_args.h)
endif ()

##==============================================================================
##
## These rules build the oesyscall target.
##
##==============================================================================
list(
  APPEND
  SOURCES
  consolefs.c
  device.c
  dirent.c
  ioctl.c
  fcntl.c
  fdtable.c
  iov.c
  mount.c
  netdb.c
  poll.c
  epoll.c
  select.c
  socket.c
  stat.c
  stdio.c
  stdlib.c
  stub.c
  syscall.c
  unistd.c
  utsname.c)

add_enclave_library(oesyscall STATIC ${SOURCES})

maybe_build_using_clangw(oesyscall)

add_enclave_dependencies(oesyscall syscall_trusted_edl)

enclave_include_directories(
  oesyscall PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
  ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

enclave_link_libraries(oesyscall oecore)
enclave_compile_options(oesyscall PRIVATE -ffunction-sections)

if (COMPILE_SYSTEM_EDL)
  enclave_compile_definitions(oesyscall PRIVATE OE_USE_BUILTIN_EDL)
endif ()

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/syscall_t.c
                            PROPERTIES COMPILE_FLAGS -DOE_NEED_STDC_NAMES)

install_enclaves(
  TARGETS
  oesyscall
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

add_subdirectory(devices)
