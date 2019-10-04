# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

## This function adds a CMake target for oedebugrt.dll. This allows the caller to add a dependency on oedebugrt.dll so
## that it will be copied to the output folder along with the target taking the dependency.
##
## TARGET_NAME: Name of the target to add for oe_debugrt. This should be unique for each caller.
##

function(copy_oedebugrt_target TARGET_NAME)

    if (UNIX)
        message(WARNING "copy_oedebugrt_target is only intended for WIN32 build environments. Check if this invocation is needed.")
    endif ()

    # Initialize the null list of dependencies for the target
    set(DEPENDENCIES "")

    # Add copy actions for the dependencies
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oedebugrt.dll
        DEPENDS oe:oedebugrt
        COMMAND ${CMAKE_COMMAND} -E copy oe:oedebugrt ${CMAKE_CURRENT_BINARY_DIR})

    # Add the dependencies to the custom target list of dependencies
    list(APPEND DEPENDENCIES
        ${CMAKE_CURRENT_BINARY_DIR}/oedebugrt.dll)

    # Always create the requested target, which may have an empty dependency list
    add_custom_target(${TARGET_NAME} DEPENDS ${DEPENDENCIES})

endfunction( copy_oedebugrt_target )
