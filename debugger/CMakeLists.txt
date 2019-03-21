# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(ptraceLib)
add_subdirectory(pythonExtension)

configure_file(oe-gdb ${OE_BINDIR}/oe-gdb)

install (PROGRAMS ${OE_BINDIR}/oe-gdb DESTINATION ${CMAKE_INSTALL_BINDIR})
