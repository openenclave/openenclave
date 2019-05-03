# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## These rules generate the edge routines for the POSIX interface, which is
## installed by oe_register_posix_ecall_function_table().
##
##==============================================================================

set(EDL_DIR ${CMAKE_SOURCE_DIR}/common)
set(EDL_FILE ${EDL_DIR}/posix.edl)

add_custom_command(
    OUTPUT posix_t.h posix_t.c posix_args.h
    DEPENDS ${EDL_FILE}
    COMMAND edger8r --search-path ${EDL_DIR} --trusted ${EDL_FILE})

add_custom_target(posix_trusted_edl
    DEPENDS posix_t.h posix_t.c posix_args.h)

##==============================================================================
##
## These rules build the oeposix target.
##
##==============================================================================

add_library(oeposix STATIC
    posix_t_wrapper.c
    array.c
    console.c
    device.c
    dirent.c
    ioctl.c
    epoll.c
    eventfd.c
    fcntl.c
    fdtable.c
    mount.c
    netdb.c
    poll.c
    select.c
    signal.c
    socket.c
    stat.c
    stdio.c
    stdlib.c
    syscall.c
    unistd.c
    utsname.c)

maybe_build_using_clangw(oeposix)

add_dependencies(oeposix posix_trusted_edl)

target_include_directories(oeposix PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oeposix oecore)

set_source_files_properties(
    ${CMAKE_CURRENT_BINARY_DIR}/posix_t.c
    PROPERTIES COMPILE_FLAGS -DOE_NEED_STDC_NAMES)

install(TARGETS oeposix EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
