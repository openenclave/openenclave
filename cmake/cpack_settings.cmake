# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# CPack package handling
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "open-enclave")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Enclave SDK")
set(CPACK_PACKAGE_CONTACT "openenclave@microsoft.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsgx-enclave-common (>=2.3.100.46354-1), libsgx-enclave-common-dev (>=2.3.100.0-1), libsgx-dcap-ql (>=1.0.100.46460-1.0), libsgx-dcap-ql-dev (>=1.0.100.46460-1.0), pkg-config")

# Cpack variables for quote verification component
set(CPACK_DEBIAN_OEQUOTE_PACKAGE_NAME "open-enclave-quote")
set(CPACK_DEBIAN_OEQUOTE_FILE_NAME DEB-DEFAULT)
set(CPACK_COMPONENT_OEQUOTE_DESCRIPTION "Open Enclave Quote Verification Library")
set(CPACK_DEBIAN_OEQUOTE_PACKAGE_DEPENDS "pkg-config")
include(CPack)
