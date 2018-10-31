# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

install (FILES lldb_sgx_plugin.py DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/sgx-plugins/lldb/)
install (FILES load_symbol_cmd.py DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger/sgx-plugins/lldb/)

