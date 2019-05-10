# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT fileencryptor_u.h fileencryptor_u.c fileencryptor_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/fileencryptor.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/fileencryptor.edl)

add_executable(file-encryptor_host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/fileencryptor_u.c)

target_include_directories(file-encryptor_host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(file-encryptor_host openenclave::oehostapp)
