# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(ptraceLib)
add_subdirectory(gdbPythonExtension)
add_subdirectory(lldbPythonExtension)

# Patch oe-gdb and oe-lldb scripts based on install location.
configure_file(oe-gdb oe-gdb)
configure_file(oe-lldb oe-lldb)

# Install oe-gdb and oe-lldb scripts upon install-time
install (PROGRAMS ${CMAKE_BINARY_DIR}/debugger/oe-gdb DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS ${CMAKE_BINARY_DIR}/debugger/oe-lldb DESTINATION ${CMAKE_INSTALL_BINDIR})
