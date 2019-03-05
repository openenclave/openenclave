# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

add_library(oehostresolver_host STATIC
    host_resolver.c
    ${resolver_u_h})

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oehostresolver_host PRIVATE -Wjump-misses-init)
endif()

#target_link_libraries(oehostresolver_host PUBLIC
#    oelibc)

target_include_directories(oehostresolver_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../../../../include/
    )

set_property(TARGET oehostresolver_host PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

install(TARGETS oehostresolver_host ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
