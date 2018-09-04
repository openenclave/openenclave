# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy MUSL headers to collector dir and wrap
# actual compilation and lib-generation happens in <ROOT>/libc/

include (ExternalProject)
ExternalProject_Add(oelibc_includes
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_LIST_DIR}/musl ${CMAKE_CURRENT_BINARY_DIR}/musl
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
        ./configure --includedir=${OE_INCDIR}/openenclave/libc CFLAGS=-fPIC
            CC=${CMAKE_C_COMPILER} CXX=${CMAKE_CXX_COMPILER}
    BUILD_COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}/musl
            make install-headers
        COMMAND $(CMAKE_COMMAND)
            -DWRAP_DST=${OE_INCDIR}/openenclave/libc/endian.h
            -DWRAP_SRC=${CMAKE_CURRENT_LIST_DIR}/musl/include/endian.h
            -DWRAP_PRE=${CMAKE_CURRENT_LIST_DIR}/endian.h.prefix
            -DWRAP_SUF=${CMAKE_CURRENT_LIST_DIR}/endian.h.suffix
            -P ${CMAKE_SOURCE_DIR}/cmake/wrap.cmake
    BUILD_BYPRODUCTS ${OE_INCDIR}/openenclave/libc ${CMAKE_CURRENT_BINARY_DIR}/musl
    INSTALL_COMMAND ""
    )

# install-rule can be generated here, usage requirements defined in <ROOT>/libc/.
install(DIRECTORY ${OE_INCDIR}/openenclave/libc DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

#
# genearl tidbits follow - find a better home
#
# To get it to build on Windows - bypassing configure - we could:
#
#BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory
#    ${CMAKE_CURRENT_SOURCE_DIR}/musl/include ${OE_INCDIR}/openenclave/libc
#    COMMAND ${CMAKE_COMMAND} -E copy_directory
#    ${CMAKE_CURRENT_SOURCE_DIR}/musl/arch/x86_64/bits ${OE_INCDIR}/openenclave/libc/bits
#
# still required creation of alltypes.h. Wrap as per above.

# This does not work with an ExternalProject_Add'ed project
#target_include_directories(oelibc_includes_copy INTERFACE ${OE_INCDIR}/openenclave/libc)
# use an interface library instead

# alternative to wrapping with newer CMake (3.10+) - use patch instead of wrap:
#find_package(Patch)
#if(!Patch_FOUND)
#  message(FATAL_ERROR "Patch command not found")
#endif()

#add_custom_command(TARGET oe_libc_includes PRE_BUILD
#    COMMAND ${CMAKE_COMMAND} -E chdir ${OE_INCDIR}/openenclave/libc ${Patch_EXECUTABLE} -p1 < ${CMAKE_SOURCE_DIR}/endian.h.patch
#    )
