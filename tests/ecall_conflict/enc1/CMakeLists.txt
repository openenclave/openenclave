# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE enc1.edl)

add_custom_command(
  OUTPUT enc1_args.h enc1_t.h enc1_t.c
  DEPENDS ../common.edl ../enc1.edl edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_enclave(
  TARGET
  ecall_conflict_enc1
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/enc1_t.c)

enclave_include_directories(ecall_conflict_enc1 PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(ecall_conflict_enc1 oelibc)

# Linux enclave build/windows host testing requires enclaves to be in enc folder
set_enclave_property(
  TARGET ecall_conflict_enc1 PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  ${CMAKE_CURRENT_BINARY_DIR}/../enc)
