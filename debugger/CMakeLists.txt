# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(ptraceLib)
add_subdirectory(pythonExtension)


# During build do an install of debugger to the output folder
set(CMAKE_INSTALL_PREFIX_BAK ${CMAKE_INSTALL_PREFIX})

set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/output)
configure_file(oe-gdb ${OE_BINDIR}/oe-gdb)

# Reset variables
set(CMAKE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX_BAK})

# Patch oe-gdb script based on install location.
configure_file(oe-gdb oe-gdb-for-install)

# Install oe-gdb script upon install-time
install (PROGRAMS ${CMAKE_BINARY_DIR}/debugger/oe-gdb-for-install DESTINATION ${CMAKE_INSTALL_BINDIR})
