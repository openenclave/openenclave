# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

add_library(oehostsocket_host STATIC
    sockhost.c
    ${socket_u_h})

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oehostsocket_host PRIVATE -Wjump-misses-init)
endif()

#target_link_libraries(oehostsocket_host PUBLIC
#    oelibc)

target_include_directories(oehostsocket_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../../../../include/
    )

set_property(TARGET oehostsocket_host PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

install(TARGETS oehostsocket_host ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
