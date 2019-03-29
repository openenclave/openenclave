# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

add_library(oeepoll_host STATIC
    hostepoll.c
    ${epoll_u_h})

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oeepoll_host PRIVATE -Wjump-misses-init)
endif()

#target_link_libraries(oeepoll_host PUBLIC
#    oelibc)

target_include_directories(oeepoll_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ../../../../include/
    )

set_property(TARGET oeepoll_host PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

install(TARGETS oeepoll_host ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)
