# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oealloc STATIC allocator.c)

target_include_directories(oealloc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include)

target_compile_options(oealloc PUBLIC -fPIC -nostdinc -fno-stack-protector)

set_source_files_properties(allocator.c
    PROPERTIES COMPILE_FLAGS "-Wno-conversion -Wno-null-pointer-arithmetic")

install(TARGETS oealloc EXPORT openenclave-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
