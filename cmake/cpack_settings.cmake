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
set(CPACK_NUGET_PACKAGE_NAME "OpenEnclave.SDK")
set(CPACK_NUGET_PACKAGE_AUTHORS "Microsoft, Confidential Computing Consortium")
set(CPACK_NUGET_PACKAGE_DESCRIPTION
    "Open Enclave (OE) is an SDK for building Trusted Applications (TA) in C and C++. An enclave application partitions itself into two components:
 - An untrusted component (called the host)
 - A trusted component (called the enclave)

The enclave executes in a protected memory region that provides confidentiality both data and code execution. These protections are provided by a Trusted Execution Environment (TEE), which is usually secured by hardware such as Intel Software Guard Extensions (SGX).

This SDK aims to generalize the development of enclave applications across TEEs from different hardware vendors. While the current implementation is focused on Intel SGX, support for ARM TrustZone is already under development.
As an open source project, this SDK also strives to provide a transparent solution that is agnostic to specific vendors, service providers and choice of operating systems.")
set(CPACK_NUGET_PACKAGE_LICENSEURL "https://github.com/openenclave/openenclave/blob/master/LICENSE")

include(CPack)
