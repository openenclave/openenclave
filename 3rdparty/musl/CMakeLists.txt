# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy MUSL headers to collector dir and wrap
# actual compilation and lib-generation happens in <ROOT>/libc/

set(CFLAGS "-fPIC -DSYSCALL_NO_INLINE")
set(PATCHES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/patches)
set(MUSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/musl)

include (ExternalProject)
ExternalProject_Add(oelibc_includes
    DOWNLOAD_COMMAND 
        ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/musl 
        ${CMAKE_CURRENT_BINARY_DIR}/musl
    PATCH_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy
            ${MUSL_DIR}/arch/x86_64/syscall_arch.h
            ${MUSL_DIR}/arch/x86_64/__syscall_arch.h
        COMMAND ${CMAKE_COMMAND} -E copy
            ${PATCHES_DIR}/syscall_arch.h
            ${MUSL_DIR}/arch/x86_64/syscall_arch.h
        COMMAND ${CMAKE_COMMAND} -E copy 
            ${PATCHES_DIR}/pthread_arch.h 
            ${MUSL_DIR}/arch/x86_64/pthread_arch.h
    CONFIGURE_COMMAND 
        ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
        ./configure 
            --includedir=${OE_INCDIR}/openenclave/libc 
            CFLAGS=${CFLAGS}
            CC=${CMAKE_C_COMPILER} 
            CXX=${CMAKE_CXX_COMPILER}
    BUILD_COMMAND 
        ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
        make install-headers
        COMMAND ${CMAKE_COMMAND} -E copy 
            ${OE_INCDIR}/openenclave/libc/endian.h
            ${OE_INCDIR}/openenclave/libc/__endian.h
        COMMAND ${CMAKE_COMMAND} -E copy 
            ${PATCHES_DIR}/endian.h
            ${OE_INCDIR}/openenclave/libc/endian.h
    BUILD_BYPRODUCTS 
        ${OE_INCDIR}/openenclave/libc ${CMAKE_CURRENT_BINARY_DIR}/musl
    INSTALL_COMMAND "")

# install-rule can be generated here, usage requirements defined in 
# <ROOT>/libc/.
install(DIRECTORY 
    ${OE_INCDIR}/openenclave/libc 
    DESTINATION 
    ${CMAKE_INSTALL_INCLUDEDIR})
