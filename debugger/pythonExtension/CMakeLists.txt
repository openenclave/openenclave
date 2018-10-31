# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(gdb)
add_subdirectory(lldb)

install (FILES oe_constants.py DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/sgx-plugins/)
install (FILES readelf.py DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/sgx-plugins/)
