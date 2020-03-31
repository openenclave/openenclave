# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

## This function adds a CMake target for the DCAP client and its dependencies provided through nuget
## redistributable packages. This allows the caller to add a dependency on these redistributables so
## that they will be copied to the output folder along with the target taking the dependency.
##
## TARGET_NAME: Name of the target to add for the DCAP client redistributables that the caller will
##              call add_dependency on. This should be unique for each caller.
##

function(add_dcap_client_target TARGET_NAME)

    if (UNIX)
        message(WARNING "import_dcap_client is only intended for WIN32 build environments. Check if this invocation is needed.")
    endif ()

    # Initialize the null list of dependencies for the target
    set(DEPENDENCIES "")

    # Define the DCAP provider path
    set(AZURE_DCAP_QUOTEPROV ${NUGET_PACKAGE_PATH}/Microsoft.Azure.DCAP/build/native/dcap_quoteprov.dll)

    # No-op if the DCAP provider is not found
    if (NOT EXISTS ${AZURE_DCAP_QUOTEPROV})
        message (WARNING "dcap_quoteprov dependencies were not found, may not execute successfully.")
    else ()
        # Add copy actions for each of the dependencies
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov.dll
            DEPENDS ${AZURE_DCAP_QUOTEPROV}
            COMMAND ${CMAKE_COMMAND} -E copy ${AZURE_DCAP_QUOTEPROV} ${CMAKE_CURRENT_BINARY_DIR})

        # Add the dependencies to the custom target list of dependencies
        list(APPEND DEPENDENCIES
            ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov.dll)
    endif ()

    # Always create the requested target, which may have an empty dependency list
    add_custom_target(${TARGET_NAME} DEPENDS ${DEPENDENCIES})

endfunction(add_dcap_client_target)
