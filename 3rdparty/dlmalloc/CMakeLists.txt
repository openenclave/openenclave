# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_enclave_library(oedlmalloc OBJECT allocator.c)

enclave_link_libraries(oedlmalloc PRIVATE oe_includes)

if (OE_TRUSTZONE)
  enclave_link_libraries(oedlmalloc PUBLIC oelibutee_includes)
  set(TEE_C_FLAGS ${OE_TZ_TA_C_FLAGS})
else ()
  set(TEE_C_FLAGS "")
endif ()

enclave_compile_options(
  oedlmalloc
  PRIVATE
  -ftls-model=local-exec
  -nostdinc
  -fPIE
  -ffreestanding
  -fvisibility=hidden
  ${TEE_C_FLAGS})

enclave_include_directories(oedlmalloc PRIVATE
                            ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

# Allow dlmallc to find required stdc functions from corelibc.
enclave_compile_definitions(oedlmalloc PRIVATE OE_NEED_STDC_NAMES)

# Specify the warning options as source files properties so that
# they will appear last in the compiler command line and supercede
# other warning options.
set_source_files_properties(
  allocator.c PROPERTIES COMPILE_FLAGS
                         "-Wno-conversion -Wno-null-pointer-arithmetic")

maybe_build_using_clangw(oedlmalloc)
