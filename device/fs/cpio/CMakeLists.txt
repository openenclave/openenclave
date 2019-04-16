# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecpio STATIC commands.c cpio.c strarr.c)

target_include_directories(oecpio PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_options(oecpio PRIVATE
    -ffreestanding)

target_link_libraries(oecpio
    PUBLIC oelibc)

set_property(TARGET oecpio PROPERTY
    ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oecpio
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
