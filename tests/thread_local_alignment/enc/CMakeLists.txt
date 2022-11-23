# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../alignment.edl)

add_custom_command(
  OUTPUT alignment_t.h alignment_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(USE_LD "")
if (UNIX)
  if (OE_USING_CLANG_10)
    find_program(OE_LLD lld-10)
  else ()
    find_program(OE_LLD lld-11)
  endif ()

  if (NOT OE_LLD)
    # Run tests with default linker. May not lock down alignment issue.
    message(
      "-- lld not found. thread_local_alignment tests require lld for lockdown alignment issues."
    )
  else ()
    set(USE_LD "-fuse-ld=lld")
  endif ()
else ()
  # On Windows lld is used by default.
endif ()

macro (alignment_enclave TBSS_ALIGNMENT TDATA_ALIGNMENT)
  set(ENCLAVE_NAME alignment_enc_${TBSS_ALIGNMENT}_${TDATA_ALIGNMENT})
  add_enclave(
    TARGET
    ${ENCLAVE_NAME}
    UUID
    71b0822f-42a3-4543-a97c-ca491f76b82c
    SOURCES
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/alignment_t.c)

  enclave_compile_definitions(
    ${ENCLAVE_NAME} PRIVATE TBSS_ALIGNMENT=${TBSS_ALIGNMENT}
    TDATA_ALIGNMENT=${TDATA_ALIGNMENT})
  enclave_include_directories(${ENCLAVE_NAME} PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})

  enclave_link_libraries(${ENCLAVE_NAME} oelibc ${USE_LD})
  maybe_build_using_clangw(${ENCLAVE_NAME})
endmacro ()

alignment_enclave(1 8)
alignment_enclave(1 16)
alignment_enclave(1 32)
alignment_enclave(1 64)
alignment_enclave(1 128)

alignment_enclave(2 8)
alignment_enclave(2 16)
alignment_enclave(2 32)
alignment_enclave(2 64)
alignment_enclave(2 128)

alignment_enclave(4 8)
alignment_enclave(4 16)
alignment_enclave(4 32)
alignment_enclave(4 64)
alignment_enclave(4 128)

alignment_enclave(8 8)
alignment_enclave(8 16)
alignment_enclave(8 32)
alignment_enclave(8 64)
alignment_enclave(8 128)

alignment_enclave(16 8)
alignment_enclave(16 16)
alignment_enclave(16 32)
alignment_enclave(16 64)
alignment_enclave(16 128)

alignment_enclave(32 8)
alignment_enclave(32 16)
alignment_enclave(32 32)
alignment_enclave(32 64)
alignment_enclave(32 128)

alignment_enclave(64 8)
alignment_enclave(64 16)
alignment_enclave(64 32)
alignment_enclave(64 64)
alignment_enclave(64 128)

alignment_enclave(128 8)
alignment_enclave(128 16)
alignment_enclave(128 32)
alignment_enclave(128 64)
alignment_enclave(128 128)
