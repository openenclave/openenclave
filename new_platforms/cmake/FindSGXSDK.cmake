if(WIN32 AND (DEFINED SGXSDKInstallPath OR DEFINED ENV{SGXSDKInstallPath}))
    if(NOT DEFINED SGXSDKInstallPath AND DEFINED ENV{SGXSDKInstallPath})
        set(SGXSDKInstallPath $ENV{SGXSDKInstallPath})
    endif()

    string(REPLACE "\\" "/" SGXSDKInstallPath ${SGXSDKInstallPath})
    string(REGEX REPLACE "/$" "" SGXSDKInstallPath ${SGXSDKInstallPath})

    set(SGX_SDK_INCLUDE_DIRS ${SGXSDKInstallPath}/include)
    set(SGX_SDK_LIBRARIES_PREFIX "${SGXSDKInstallPath}/bin/${CMAKE_VS_PLATFORM_NAME}")

    if(NOT EXISTS ${SGX_SDK_INCLUDE_DIRS})
        unset(SGX_SDK_INCLUDE_DIRS)
        unset(SGX_SDK_LIBRARIES_PREFIX)
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SDGSDK REQUIRED_VARS SGX_SDK_INCLUDE_DIRS SGX_SDK_LIBRARIES_PREFIX)
