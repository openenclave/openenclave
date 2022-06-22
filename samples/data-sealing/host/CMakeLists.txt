# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_edl(../datasealing.edl UNTRUSTED .)

add_executable(data-sealing_host host.cpp
                                 ${CMAKE_CURRENT_BINARY_DIR}/datasealing_u.c)

if (WIN32)
  copy_oedebugrt_target(data-sealing_host_oedebugrt)
  add_dependencies(data-sealing_host data-sealing_host_oedebugrt)
endif ()

target_include_directories(
  data-sealing_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(data-sealing_host openenclave::oehost)
