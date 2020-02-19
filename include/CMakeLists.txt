# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# OE main include files, add interface library, add install steps

add_library(oe_includes INTERFACE)
add_dependencies(oe_includes oe_includes_place)
target_include_directories(oe_includes INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>)
install(DIRECTORY openenclave/bits DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/ COMPONENT OEHOSTVERIFY)
install(DIRECTORY openenclave/edger8r DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/)
install(FILES openenclave/enclave.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/)
install(FILES openenclave/host.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/)
install(FILES openenclave/host_verify.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/ COMPONENT OEHOSTVERIFY)
install(FILES openenclave/attestation/plugin.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/attestation/ COMPONENT OEHOSTVERIFY)
install(FILES openenclave/attestation/sgx/attester.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/attestation/sgx/)
install(FILES openenclave/attestation/sgx/verifier.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave/attestation/sgx/ COMPONENT OEHOSTVERIFY)
install(TARGETS oe_includes EXPORT openenclave-targets)
