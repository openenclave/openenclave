# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(EDL_DIR ${CMAKE_SOURCE_DIR}/io/edl)
set(EDL_FILE ${EDL_DIR}/oeio.edl)

add_custom_command(
    OUTPUT oeio_t.h oeio_t.c oeio_args.h
    DEPENDS ${EDL_FILE}
    COMMAND edger8r --search-path ${EDL_DIR} --trusted ${EDL_FILE})

add_custom_target(oeio_trusted_edl DEPENDS oeio_t.h oeio_t.c oeio_args.h)

add_library(oeioenc STATIC
    oeio_t_wrapper.c
    array.c
    console.c
    cwd.c
    device.c
    epoll.c
    eventfd.c
    eventfd_device.c
    exit.c
    fd.c
    fs.c
    getdomainname.c
    gethostname.c
    hostepoll_device.c
    hostfs_device.c
    hostresolver_device.c
    hostsock_device.c
    ids.c
    mount.c
    poll.c
    realpath.c
    resolver.c
    select.c
    signal.c
    sleep.c
    socket.c
    stdio.c
    syscall.c
    uname.c)

add_dependencies(oeioenc oeio_trusted_edl)

target_include_directories(oeioenc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeioenc oecore)

set_source_files_properties(
    ${CMAKE_CURRENT_BINARY_DIR}/oeio_t.c
    PROPERTIES COMPILE_FLAGS -DOE_NEED_STDC_NAMES)

target_include_directories(oeioenc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

install(TARGETS oeioenc EXPORT openenclave-targets ARCHIVE
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
