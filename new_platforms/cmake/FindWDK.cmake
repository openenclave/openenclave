# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# NOTE: Hosted Visual Studio 2017 instances in Azure DevOps for Continuous
# Integration (CI) do not have the WDK installed. We work around this by having
# CI download a custom WDK package that has the files we need, and nothing more
# seeing as installing the WDK from the official package is not trivial. This
# is what the WDKCIOverride environment variable is used for.

# When the WDK is installed, its headers are integrated into the readily
# installed Windows SDK. One folder however is specific to the WDK, namely 'km'
# for driver development. We test for it to see if the WDK is installed. Since
# the headers are integrated into the SDK, there is no need to pass any
# WDK-specific include paths to the MSVC compiler, except if headers under 'km'
# are needed, which we do not.

if(DEFINED ENV{WDKCIOverride})
    set(WDK_PATH $ENV{WDKCIOverride})
elseif(DEFINED ENV{WDKContentRoot})
    set(WDK_PATH_TEST "$ENV{WDKContentRoot}/Include/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/km")
else()
    set(WDK_PATH_TEST "$ENV{ProgramFiles\(x86\)}/Windows Kits/10/Include/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/km")
endif()

if(DEFINED WDK_PATH_TEST)
    if(EXISTS ${WDK_PATH_TEST})
        string(REPLACE "/km" "" WDK_PATH ${WDK_PATH_TEST})
    endif()

    unset(WDK_PATH_TEST)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WDK REQUIRED_VARS WDK_PATH)
