# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oestart STATIC sgx/start.S)

maybe_build_using_clangw(oestart)

target_link_libraries(oestart PUBLIC oe_includes oecore)

install(TARGETS oestart EXPORT openenclave-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
