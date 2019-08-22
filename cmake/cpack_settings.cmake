# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# CPack variables for the regular OE SDK.
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "open-enclave")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Enclave SDK")
set(CPACK_PACKAGE_CONTACT "openenclave@microsoft.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsgx-enclave-common (>=2.3.100.46354-1), libsgx-enclave-common-dev (>=2.3.100.0-1), libsgx-dcap-ql (>=1.0.100.46460-1.0), libsgx-dcap-ql-dev (>=1.0.100.46460-1.0), pkg-config")

# CPack variables for the non-enclave host verification package.
# We match the naming convention of the OE SDK package by setting the
# CPACK_DEBIAN_OEHOSTVERIFY_FILE_NAME field.
set(CPACK_DEBIAN_OEHOSTVERIFY_PACKAGE_NAME "open-enclave-hostverify")
set(CPACK_DEBIAN_OEHOSTVERIFY_FILE_NAME "${CPACK_DEBIAN_OEHOSTVERIFY_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-Linux.deb")
set(CPACK_COMPONENT_OEHOSTVERIFY_DESCRIPTION "Open Enclave Report Verification Host Library")
set(CPACK_DEBIAN_OEHOSTVERIFY_PACKAGE_DEPENDS "pkg-config")
include(CPack)
