# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Build the IDL enclave library

add_library(oeidl STATIC
    typeinfo.c
    )

target_compile_options(oeidl PRIVATE
    -Wmissing-prototypes
    -Wstrict-prototypes
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-__vfprintf_chk
    -fno-builtin-__memset_chk
    -fPIC
    -m64)

# oeidl and its dependents need the OE includes to compile
target_link_libraries(oeidl PUBLIC oe_includes)

# assemble lib-archive into proper dir
set_property(TARGET oeidl PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

# install lib-archive upon install-time
install (TARGETS oeidl EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
