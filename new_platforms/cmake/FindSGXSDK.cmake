# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(WIN32 AND (DEFINED SGXSDKInstallPath OR DEFINED ENV{SGXSDKInstallPath}))
    if(NOT DEFINED SGXSDKInstallPath AND DEFINED ENV{SGXSDKInstallPath})
        set(SGXSDKInstallPath $ENV{SGXSDKInstallPath})
    endif()

    string(REPLACE "\\" "/" SGXSDKInstallPath ${SGXSDKInstallPath})
    string(REGEX REPLACE "/$" "" SGXSDKInstallPath ${SGXSDKInstallPath})

    set(SGX_SDK_INCLUDE_DIRS ${SGXSDKInstallPath}/include)
    set(SGX_SDK_LIBRARIES_PREFIX ${SGXSDKInstallPath}/bin/${CMAKE_VS_PLATFORM_NAME})
    set(SGX_SDK_EDGER8R_TOOL ${SGXSDKInstallPath}/bin/win32/release/sgx_edger8r.exe)
    set(SGX_SDK_SIGN_TOOL ${SGXSDKInstallPath}/bin/${CMAKE_VS_PLATFORM_NAME}/release/sgx_sign.exe)

    if(NOT EXISTS ${SGX_SDK_INCLUDE_DIRS} OR
       NOT EXISTS ${SGX_SDK_LIBRARIES_PREFIX} OR
       NOT EXISTS ${SGX_SDK_EDGER8R_TOOL} OR
       NOT EXISTS ${SGX_SDK_SIGN_TOOL})
        unset(SGX_SDK_INCLUDE_DIRS)
        unset(SGX_SDK_LIBRARIES_PREFIX)
        unset(SGX_SDK_EDGER8R_TOOL)
        unset(SGX_SDK_SIGN_TOOL)
    endif()
endif()

set(SGX_SDK_EDGER8R_TOOL ${SGX_SDK_EDGER8R_TOOL} PARENT_SCOPE)
set(SGX_SDK_SIGN_TOOL ${SGX_SDK_SIGN_TOOL} PARENT_SCOPE)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SGXSDK REQUIRED_VARS
    SGX_SDK_INCLUDE_DIRS
    SGX_SDK_LIBRARIES_PREFIX
    SGX_SDK_EDGER8R_TOOL
    SGX_SDK_SIGN_TOOL)
