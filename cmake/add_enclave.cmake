# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to sign an enclave binary.
#
# Usage:
#
#  add_enclave(<TARGET target>
#              [CXX]
#              <SOURCES sources>
#              [<CONFIG config>]
#              [<KEY key>])
#
# Given <target> and <config>, this function adds custom commands to
# generate a signing key if key is not specified and call `oesign` to
# sign the target, resulting in `<target>.signed`. It also adds
# `<target>_signed` as an imported target so that it can be referenced
# later in the CMake graph.
#
# The target is always linked to `oeenclave`, and if the optional flag
# `CXX` is passed, it is also linked to `oelibcxx`
#
# TODO: (1) Replace the name guessing logic.
# TODO: (2) Setup the dependency using `${BIN}_signed` instead of the
# default custom target.
# TODO: (3) Validate arguments into this function
function(add_enclave)

   set(options CXX)
   set(oneValueArgs TARGET CONFIG KEY)
   set(multiValueArgs SOURCES)
   cmake_parse_arguments(ENCLAVE
     "${options}"
     "${oneValueArgs}"
     "${multiValueArgs}"
     ${ARGN})

   add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
   target_link_libraries(${ENCLAVE_TARGET} oeenclave)
   if (ENCLAVE_CXX)
     target_link_libraries(${ENCLAVE_TARGET} oelibcxx)
   endif ()
   
  # Cross-compile if needed.
  if (USE_CLANGW)
    maybe_build_using_clangw(${ENCLAVE_TARGET})
    
    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX "${CMAKE_STATIC_LIBRARY_PREFIX}" PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}" PARENT_SCOPE)

    # Propagate library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY "${CMAKE_C_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY "${CMAKE_CXX_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)

    # Propagate linker variables
    set(CMAKE_EXECUTABLE_SUFFIX "${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES}" PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE}" PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES}" PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE}" PARENT_SCOPE)

    # Propagate cpmpiler variables
    set(CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}" PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}" PARENT_SCOPE)
  endif()

   if (NOT ENCLAVE_CONFIG)
      # Since the config is not specified, the enclave wont be signed.
      return()
   endif ()

  # Generate the signing key.
  if(NOT ENCLAVE_KEY)
     add_custom_command(OUTPUT ${ENCLAVE_TARGET}-private.pem
       COMMAND openssl genrsa -out ${ENCLAVE_TARGET}-private.pem -3 3072)
     set(ENCLAVE_KEY  ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_TARGET}-private.pem)
  endif()

  # TODO: Get this name intelligently (somehow use $<TARGET_FILE> with
  # `.signed` injected).
  set(SIGNED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/${ENCLAVE_TARGET}.signed)

  # Sign the enclave using `oesign`.
  if(ENCLAVE_CONFIG)
    add_custom_command(OUTPUT ${SIGNED_LOCATION}
      COMMAND oesign sign -e $<TARGET_FILE:${ENCLAVE_TARGET}> -c ${ENCLAVE_CONFIG} -k ${ENCLAVE_KEY}
      DEPENDS oesign ${ENCLAVE_TARGET} ${ENCLAVE_CONFIG} ${ENCLAVE_KEY}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  endif()

  # Import the generated signed enclave so we can reference it with
  # `$<TARGET_FILE>` later.
  add_library(${ENCLAVE_TARGET}_signed SHARED IMPORTED GLOBAL)
  set_target_properties(${ENCLAVE_TARGET}_signed PROPERTIES
    IMPORTED_LOCATION ${SIGNED_LOCATION})

  # Add a custom target with `ALL` semantics so these targets are always built.
  add_custom_target(${ENCLAVE_TARGET}_signed_target ALL DEPENDS ${SIGNED_LOCATION})
endfunction()
