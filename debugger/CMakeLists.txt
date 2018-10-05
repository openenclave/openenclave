# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(ptraceLib)
add_subdirectory(pythonExtension)

# Patch oe-gdb script based on install location.
configure_file(oe-gdb oe-gdb)

# Install oe-gdb script upon install-time
install (PROGRAMS ${CMAKE_BINARY_DIR}/debugger/oe-gdb DESTINATION ${CMAKE_INSTALL_BINDIR})
