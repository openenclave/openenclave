# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Copy files during build
configure_file(
  gdb_sgx_plugin.py
  ${OE_LIBDIR}/openenclave/debugger/gdb-sgx-plugin/gdb_sgx_plugin.py COPYONLY)
configure_file(
  load_symbol_cmd.py
  ${OE_LIBDIR}/openenclave/debugger/gdb-sgx-plugin/load_symbol_cmd.py COPYONLY)
configure_file(
  readelf.py ${OE_LIBDIR}/openenclave/debugger/gdb-sgx-plugin/readelf.py
  COPYONLY)

# Installation
install(
  FILES gdb_sgx_plugin.py
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/gdb-sgx-plugin/)
install(
  FILES load_symbol_cmd.py
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/gdb-sgx-plugin/)
install(
  FILES readelf.py
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/gdb-sgx-plugin/)
