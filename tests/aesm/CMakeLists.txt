# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(aesm main.cpp)
target_link_libraries(aesm oehost)

# Additional compilation and link options when using libsgx
if(USE_LIBSGX)
add_dependencies(aesm libsgx_includes libsgx_urts)
target_include_directories(aesm PUBLIC
    $<BUILD_INTERFACE:${OE_INCDIR}/openenclave/libsgx>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/openenclave/libsgx>
    )
target_link_libraries(aesm libsgxoeql libsgx_urts)
target_compile_definitions(aesm PRIVATE OE_USE_LIBSGX)

# Signed QE and PCE enclave binaries need to be in the same folder
add_custom_command(OUTPUT aesm.libsgx_pce
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OE_BINDIR}/libsgx/libsgx_pce.signed.so .
    DEPENDS ${OE_BINDIR}/libsgx/libsgx_pce.signed.so
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
add_custom_command(OUTPUT aesm.libsgx_qe3
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OE_BINDIR}/libsgx/libsgx_qe3.signed.so .
    DEPENDS ${OE_BINDIR}/libsgx/libsgx_qe3.signed.so
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
add_custom_target(aesm.dependencies ALL
    DEPENDS aesm.libsgx_pce aesm.libsgx_qe3
    )
endif()

add_test(NAME tests/aesm COMMAND ./aesm)
set_tests_properties(tests/aesm PROPERTIES SKIP_RETURN_CODE 2)
