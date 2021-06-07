# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Copy files during build
configure_file(
  lldb_sgx_plugin.py
  ${OE_LIBDIR}/openenclave/debugger/lldb-sgx-plugin/lldb_sgx_plugin.py COPYONLY)

# Installation
install(
  FILES lldb_sgx_plugin.py
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/lldb-sgx-plugin/)
