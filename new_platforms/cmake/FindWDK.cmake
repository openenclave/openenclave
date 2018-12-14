if(DEFINED ENV{WDKContentRoot})
    file(GLOB WDK_PATH "$ENV{WDKContentRoot}/Include/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/km")
else()
    file(GLOB WDK_PATH "$ENV{ProgramFiles\(x86\)}/Windows Kits/10/Include/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/km")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WDK REQUIRED_VARS WDK_PATH)

if (NOT WDK_PATH)
    return()
endif()
