# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

## This function adds a CMake target for the DCAP client and its dependencies provided through nuget
## redistributable packages. This allows the caller to add a dependency on these redistributables so
## that they will be copied to the output folder along with the target taking the dependency.
## 
## TARGET_NAME: Name of the target to add for the DCAP client redistributables that the caller will
##              call add_dependency on. This should be unique for each caller.
## 

function(add_dcap_client_target TARGET_NAME)

    if (NOT WIN32)
        message(WARNING "import_dcap_client is only intended for WIN32 build environments. Check if this invocation is needed.")
    endif ()

    if (CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebugInfo)
        set(IMPORT_BUILD_TYPE Debug)
    elseif (CMAKE_BUILD_TYPE MATCHES Release OR CMAKE_BUILD_TYPE MATCHES MinSizeRel)
        set(IMPORT_BUILD_TYPE Release)
    else ()
        message(FATAL_ERROR "Unsupported CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}, import_dcap_client needs to be updated to support it.")
    endif ()

    # Initialize the null list of dependencies for the target
    set(DEPENDENCIES "")

    # Define the DCAP provider paths
    set(AZURE_DCAP_QUOTEPROV ${CMAKE_SOURCE_DIR}/prereqs/nuget/Microsoft.Azure.DCAP.Client/lib/${IMPORT_BUILD_TYPE}/dcap_quoteprov.dll)
    set(AZURE_DCAP_QUOTEPROV_SYMBOLS ${CMAKE_SOURCE_DIR}/prereqs/nuget/Microsoft.Azure.DCAP.Client/lib/${IMPORT_BUILD_TYPE}/dcap_quoteprov.pdb)

    # Note that for all of dcap_quoteprov's own dependencies, we always take the Release build.
    # The Debug versions don't come with symbols anyway and take a dependency on the debug msvcr110d.dll
    # which is not provided by the vcredist_x64 package and will cause runtime load faiures.
    set(LIBCURL ${CMAKE_SOURCE_DIR}/prereqs/nuget/curl.redist/build/native/bin/v110/x64/Release/dynamic/libcurl.dll)
    set(LIBSSH2 ${CMAKE_SOURCE_DIR}/prereqs/nuget/libssh2.redist/build/native/bin/v110/x64/Release/dynamic/cdecl/libssh2.dll)
    set(LIBEAY32 ${CMAKE_SOURCE_DIR}/prereqs/nuget/openssl.redist/build/native/bin/v110/x64/Release/dynamic/cdecl/libeay32.dll)
    set(SSLEAY32 ${CMAKE_SOURCE_DIR}/prereqs/nuget/openssl.redist/build/native/bin/v110/x64/Release/dynamic/cdecl/ssleay32.dll)
    set(ZLIB ${CMAKE_SOURCE_DIR}/prereqs/nuget/zlib.redist/build/native/bin/v110/x64/Release/dynamic/cdecl/zlib.dll)

    # No-op if the DCAP provider is not found
    if (NOT EXISTS ${AZURE_DCAP_QUOTEPROV})
        message (WARNING "dcap_quoteprov dependencies were not found, may not execute successfully.")
    else ()
        if (NOT EXISTS ${LIBCURL})
            message(FATAL_ERROR "Found Azure dcap_quoteprov, but could not find its dependency ${LIBCURL}, aborting.")
        endif ()
        if (NOT EXISTS ${LIBSSH2})
            message(FATAL_ERROR "Found Azure dcap_quoteprov, but could not find its dependency ${LIBSSH2}, aborting.")
        endif ()
        if (NOT EXISTS ${LIBEAY32})
            message(FATAL_ERROR "Found Azure dcap_quoteprov, but could not find its dependency ${LIBEAY32}, aborting.")
        endif ()
        if (NOT EXISTS ${SSLEAY32})
            message(FATAL_ERROR "Found Azure dcap_quoteprov, but could not find its dependency ${SSLEAY32}, aborting.")
        endif ()
        if (NOT EXISTS ${ZLIB})
            message(FATAL_ERROR "Found Azure dcap_quoteprov, but could not find its dependency ${ZLIB}, aborting.")
        endif ()

        # Add copy actions for each of the dependencies
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov.dll
            DEPENDS ${AZURE_DCAP_QUOTEPROV}
            COMMAND ${CMAKE_COMMAND} -E copy ${AZURE_DCAP_QUOTEPROV} ${CMAKE_CURRENT_BINARY_DIR})

        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libcurl.dll
            DEPENDS ${LIBCURL}
            COMMAND ${CMAKE_COMMAND} -E copy ${LIBCURL} ${CMAKE_CURRENT_BINARY_DIR})
            
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libssh2.dll
            DEPENDS ${LIBSSH2}
            COMMAND ${CMAKE_COMMAND} -E copy ${LIBSSH2} ${CMAKE_CURRENT_BINARY_DIR})
            
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libeay32.dll
            DEPENDS ${LIBEAY32}
            COMMAND ${CMAKE_COMMAND} -E copy ${LIBEAY32} ${CMAKE_CURRENT_BINARY_DIR})
            
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ssleay32.dll
            DEPENDS ${SSLEAY32}
            COMMAND ${CMAKE_COMMAND} -E copy ${SSLEAY32} ${CMAKE_CURRENT_BINARY_DIR})
            
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/zlib.dll
            DEPENDS ${ZLIB}
            COMMAND ${CMAKE_COMMAND} -E copy ${ZLIB} ${CMAKE_CURRENT_BINARY_DIR})

        # Add the dependencies to the custom target list of dependencies
        list(APPEND DEPENDENCIES
            ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov.dll
            ${CMAKE_CURRENT_BINARY_DIR}/libcurl.dll
            ${CMAKE_CURRENT_BINARY_DIR}/libssh2.dll
            ${CMAKE_CURRENT_BINARY_DIR}/libeay32.dll
            ${CMAKE_CURRENT_BINARY_DIR}/ssleay32.dll
            ${CMAKE_CURRENT_BINARY_DIR}/zlib.dll)

        # Optionally check for the DCAP provider symbols and add those as well to the list
        if (EXISTS ${AZURE_DCAP_QUOTEPROV_SYMBOLS})
            add_custom_command(
                OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov.pdb
                DEPENDS ${AZURE_DCAP_QUOTEPROV_SYMBOLS}
                COMMAND ${CMAKE_COMMAND} -E copy ${AZURE_DCAP_QUOTEPROV_SYMBOLS} ${CMAKE_CURRENT_BINARY_DIR})
            list(APPEND DEPENDENCIES ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov.pdb)
        endif ()
    endif ()

    # Always create the requested target, which may have an empty dependency list
    add_custom_target(${TARGET_NAME} DEPENDS ${DEPENDENCIES})

endfunction(add_dcap_client_target)
