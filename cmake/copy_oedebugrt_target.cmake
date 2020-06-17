# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

## This function adds a CMake target for oedebugrt.dll. This allows the caller to :add a dependency on oedebugrt.dll so
## that it will be copied to the output folder along with the target taking the dependency.
## When the host executable is launched under windbg, if edebugrt.dll is present in the same path as the host executable,
## it gets automatically loaded into the debugger. This enables windbg to debug enclave applications.
##
## TARGET_NAME: Name of the target to add for oe_debugrt. This should be unique for each caller.
##

function (copy_oedebugrt_target TARGET_NAME)

  if (UNIX)
    message(
      WARNING
        "copy_oedebugrt_target is only intended for WIN32 build environments. Check if this invocation is needed."
    )
  endif ()

  get_property(
    OEDEBUGRTLOCATION
    TARGET openenclave::oedebugrt
    PROPERTY LOCATION)
  # Add copy actions for the dependencies
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oedebugrt.dll
    DEPENDS ${OEDEBUGRTLOCATION}
    COMMAND ${CMAKE_COMMAND} -E copy ${OEDEBUGRTLOCATION}
            ${CMAKE_CURRENT_BINARY_DIR})

  get_filename_component(OEDEBUGRTFOLDER "${OEDEBUGRTLOCATION}" DIRECTORY)
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/oedebugrt.pdb
    DEPENDS ${OEDEBUGRTFOLDER}/oedebugrt.pdb
    COMMAND ${CMAKE_COMMAND} -E copy ${OEDEBUGRTFOLDER}/oedebugrt.pdb
            ${CMAKE_CURRENT_BINARY_DIR})

  # Always create the requested target, which may have an empty dependency list
  add_custom_target(
    ${TARGET_NAME} DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/oedebugrt.dll
                           ${CMAKE_CURRENT_BINARY_DIR}/oedebugrt.pdb)

endfunction (copy_oedebugrt_target)
