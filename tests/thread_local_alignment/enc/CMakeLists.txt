# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread_local_alignment.edl)

add_custom_command(
  OUTPUT thread_local_alignment_t.h thread_local_alignment_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET thread_local_alignment_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/thread_local_alignment_t.c)

enclave_include_directories(thread_local_alignment_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

# To test the Windows behavior on Linux, we need to use lld (uncomment the command below).
# Given that lld is currently not a dependency of the OE on Linux, we still use the
# default linker (ld).
#enclave_link_libraries(thread_local_alignment_enc -fuse-ld=lld)
