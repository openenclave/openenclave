# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# CPack variables for the regular OE SDK.
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "open-enclave")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Enclave SDK")
set(CPACK_PACKAGE_CONTACT "oesdk@lists.confidentialcomputing.io")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/cmake/NuGetDescription.txt")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# CPack variables for Debian packages
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsgx-enclave-common (>=2.3.100.46354-1), libsgx-enclave-common-dev (>=2.3.100.0-1), libsgx-dcap-ql (>=1.0.100.46460-1.0), libsgx-dcap-ql-dev (>=1.0.100.46460-1.0)")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "pkg-config")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

# CPack variables for the non-enclave host verification package.
# We match the naming convention of the OE SDK package by setting the
# CPACK_DEBIAN_OEHOSTVERIFY_FILE_NAME field.
set(CPACK_DEBIAN_OEHOSTVERIFY_PACKAGE_NAME "open-enclave-hostverify")
set(CPACK_DEBIAN_OEHOSTVERIFY_PACKAGE_DEPENDS "")
set(CPACK_DEBIAN_OEHOSTVERIFY_PACKAGE_RECOMMENDS "pkg-config")
set(CPACK_DEBIAN_OEHOSTVERIFY_FILE_NAME DEB-DEFAULT)
set(CPACK_COMPONENT_OEHOSTVERIFY_DESCRIPTION "Open Enclave Report Verification Host Library")

# CPack variables for Nuget packages
set(CPACK_NUGET_PACKAGE_NAME "open-enclave")
set(CPACK_NUGET_PACKAGE_AUTHORS "Open Enclave SDK Contributors")
set(CPACK_NUGET_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_NUGET_PACKAGE_LICENSEURL "https://github.com/openenclave/openenclave/blob/master/LICENSE")

include(CPack)
