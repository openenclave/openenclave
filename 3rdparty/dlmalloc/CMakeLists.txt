# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oedlmalloc_obj OBJECT allocator.c)

enclave_link_libraries(oedlmalloc_obj PRIVATE oe_includes oelibc_includes)

if (OE_TRUSTZONE)
  enclave_link_libraries(oedlmalloc_obj PUBLIC oelibutee_includes)
  set(TEE_C_FLAGS ${OE_TZ_TA_C_FLAGS})
else ()
  set(TEE_C_FLAGS "")
endif ()

enclave_compile_options(
  oedlmalloc_obj
  PRIVATE
  -ftls-model=local-exec
  -nostdinc
  -fPIE
  -ffreestanding
  -fvisibility=hidden
  ${TEE_C_FLAGS})

# Specify the warning options as source files properties so that
# they will appear last in the compiler command line and supercede
# other warning options.
set_source_files_properties(
  allocator.c PROPERTIES COMPILE_FLAGS
                         "-Wno-conversion -Wno-null-pointer-arithmetic")

maybe_build_using_clangw(oedlmalloc_obj)

install_enclaves(
  TARGETS
  oedlmalloc_obj
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
