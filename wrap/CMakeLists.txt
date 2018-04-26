# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include_directories(${CMAKE_SOURCE_DIR}/3rdparty/musl/musl/include)
include_directories(${CMAKE_BINARY_DIR}/output/include/openenclave/libc)
add_library(fops STATIC f_ops.c )
add_dependencies(fops oelibc_includes)
target_link_libraries(fops oeenclave )

target_compile_options(fops PRIVATE  -Wno-error)


# assemble lib-archive into proper dir
set_property(TARGET fops PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

# install lib-archive upon install-time
install (TARGETS fops  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)


