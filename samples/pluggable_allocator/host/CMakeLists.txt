# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT allocator_demo_u.h allocator_demo_u.c allocator_demo_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/allocator_demo.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/allocator_demo.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(allocator_demo_host
               host.cpp ${CMAKE_CURRENT_BINARY_DIR}/allocator_demo_u.c)

if (WIN32)
  copy_oedebugrt_target(allocator_demo_host_oedebugrt)
  add_dependencies(allocator_demo_host allocator_demo_host_oedebugrt)
endif ()

target_include_directories(
  allocator_demo_host PRIVATE # Needed for the generated file allocator_demo_u.h
                              ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(allocator_demo_host openenclave::oehost)
