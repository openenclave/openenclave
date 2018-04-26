# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Copy libsgx headers and libs to collector directories
# TODO: Replace temporary http endpoint for prebuilt package download with actual
# Intel published location when available
include (ExternalProject)
ExternalProject_Add(libsgx_includes
    DOWNLOAD_COMMAND wget http://10.224.140.70:8888/libsgx.tar.gz -P ${CMAKE_CURRENT_LIST_DIR}
        COMMAND tar -zxvf ${CMAKE_CURRENT_LIST_DIR}/libsgx.tar.gz --overwrite --directory ${CMAKE_CURRENT_LIST_DIR}
        COMMAND rm -rf ${CMAKE_CURRENT_LIST_DIR}/libsgx.tar.gz
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/libsgx/include ${OE_INCDIR}/openenclave/libsgx
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/libsgx/lib ${OE_LIBDIR}/openenclave/host
        # ATTN: signed QE and PCE .so files must be in the same location as libsgx_urts.so
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/libsgx/bin ${OE_LIBDIR}/openenclave/host
    INSTALL_COMMAND ""
    )

install (DIRECTORY ${OE_LIBDIR}/openenclave/host DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave)

add_library(libsgx_enclave_common SHARED IMPORTED GLOBAL)
set_target_properties(libsgx_enclave_common PROPERTIES
    IMPORTED_LOCATION ${OE_LIBDIR}/openenclave/host/libsgx_enclave_common.so
    )

add_library(libsgx_urts SHARED IMPORTED GLOBAL)
set_target_properties(libsgx_urts PROPERTIES
    IMPORTED_LOCATION ${OE_LIBDIR}/openenclave/host/libsgx_urts.so
    )

add_library(libsgxoeql SHARED IMPORTED GLOBAL)
set_target_properties(libsgxoeql PROPERTIES
    IMPORTED_LOCATION ${OE_LIBDIR}/openenclave/host/libsgxoeql.so
    # ATTN: Workaround for libsgxoeql.so being built with no -soname
    IMPORTED_NO_SONAME true
    )
