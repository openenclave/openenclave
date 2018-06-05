# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include_directories(${CMAKE_SOURCE_DIR}/3rdparty/musl/musl/include)
include_directories(${CMAKE_BINARY_DIR}/output/include/openenclave/libc)
add_library(libcio STATIC fileio.c)
add_dependencies(libcio oelibc_includes)
target_link_libraries(libcio oelibc)

target_compile_options(libcio PRIVATE -Wno-error)


# assemble lib-archive into proper dir
set_property(TARGET libcio PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

# install lib-archive upon install-time
install (TARGETS libcio ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)


