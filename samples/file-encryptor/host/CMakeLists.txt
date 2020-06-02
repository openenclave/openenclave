# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT fileencryptor_u.h fileencryptor_u.c fileencryptor_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/fileencryptor.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/fileencryptor.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(file-encryptor_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/fileencryptor_u.c)

if (WIN32)
  copy_oedebugrt_target(file-encryptor_host_oedebugrt)
  add_dependencies(file-encryptor_host file-encryptor_host_oedebugrt)
endif ()

target_include_directories(
  file-encryptor_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(file-encryptor_host openenclave::oehost)
