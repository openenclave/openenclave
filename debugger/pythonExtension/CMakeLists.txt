# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(gdbPythonExtension)
add_subdirectory(lldbPythonExtension)

install (FILES readelf.py DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/sgx-plugins/)
