# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
add_custom_command(
  OUTPUT name_conflict_t.h name_conflict_t.c name_conflict_args.h
  DEPENDS edger8r ../name_conflict.edl
  COMMAND
    edger8r --trusted name_conflict.edl --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR}/..)

add_enclave(
  TARGET
  name_conflict_enc
  UUID
  15056a35-a9ae-4c5e-a118-3ff174d61579
  SOURCES
  enc.c
  name_conflict_t.c)

add_subdirectory(crypto)
add_subdirectory(dl)

enclave_include_directories(
  name_conflict_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto ${CMAKE_CURRENT_SOURCE_DIR}/dl)
enclave_link_libraries(name_conflict_enc oelibc crypto dl)
