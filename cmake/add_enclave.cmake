# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to sign an enclave binary.
#
# Usage:
#
#	add_enclave(<TARGET target> <SOURCES sources> <CONFIG config> <KEY key>)
#
# Given <target> and <CONFIG>, this function adds custom
# commands to generate a signing key if key is not specified
# and call `oesign` to sign the
# target, resulting in `<target>.signed.so`. It also adds
# `<target>_signed` as an imported target so that it can be referenced
# later in the CMake graph.
# TODO: (1) Replace the name guessing logic.
# TODO: (2) Setup the dependency using `${BIN}_signed` instead of the
# default custom target.
# TODO: (3) Validate arguments into this function
function(add_enclave)

   set(options)
   set(oneValueArgs TARGET CONFIG KEY)
   set(multiValueArgs SOURCES)
   cmake_parse_arguments(ENCLAVE "${options}" "${oneValueArgs}"
                          "${multiValueArgs}" ${ARGN})
   add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
   
   if(NOT ENCLAVE_CONFIG)
      return()
   endif()

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
      COMMAND oesign sign $<TARGET_FILE:${ENCLAVE_TARGET}> ${ENCLAVE_CONFIG} ${ENCLAVE_KEY} 
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
