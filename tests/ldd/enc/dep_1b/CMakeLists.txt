# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Build enclave shared object dependency
set(LDD_TEST_DEP_SUFFIX 1b)
set(LDD_TEST_DEP_MAGIC 1002)
configure_file(../dep_common.c.in dep_common.c)

add_library(ldd_enc_dep_1b SHARED dep_common.c)
set_target_properties(ldd_enc_dep_1b PROPERTIES LIBRARY_OUTPUT_DIRECTORY
                                                ${LDD_TEST_ENC_DIR})
target_include_directories(ldd_enc_dep_1b PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(
  ldd_enc_dep_1b
  PUBLIC -fPIC -nostdinc -fstack-protector-strong
         # Preserve frame-pointer in Release mode to enable oe_backtrace.
         -fno-omit-frame-pointer)

target_link_libraries(
  ldd_enc_dep_1b
  PRIVATE -nostdlib
          -nodefaultlibs
          -nostartfiles
          # Removed -Bsymbolic to trigger generation of relocations.
          # Removed -pie to create a shared library and instead used pic.
          -Wl,--no-undefined,-Bstatic,--export-dynamic,-pic,--build-id
          -Wl,-z,noexecstack
          -Wl,-z,now
          -Wl,-gc-sections)
