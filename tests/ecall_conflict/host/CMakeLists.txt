# Copyright (c) Open Enclave SDK contributors. Licensed under the MIT License.

add_custom_command(
  OUTPUT enc1_args.h enc1_u.h enc1_u.c enc2_args.h enc2_u.h enc2_u.c
  COMMAND
    edger8r --untrusted enc1.edl enc2.edl ${DEFINE_OE_SGX} --search-path
    ${PROJECT_SOURCE_DIR}/include --search-path ${CMAKE_CURRENT_SOURCE_DIR}/..
  DEPENDS ../common.edl ../enc1.edl ../enc2.edl edger8r)

add_executable(ecall_conflict_host enc1_u.c enc2_u.c host.cpp)

target_include_directories(ecall_conflict_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ecall_conflict_host oehost)
