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
  PUBLIC
    -fPIC
    -nostdinc
    -fstack-protector-strong
    # The secondary modules are compiled with -ftls-model=initial-exec flag.
    # This informs the compiler that the modules will be loaded along with the main module,
    # rather than being dynamically loaded via dlopen. In this case, the compiler
    # will generate R_X86_64_TPOFF relocations for thread-local variables.
    -ftls-model=initial-exec
    # Preserve frame-pointer in Release mode to enable oe_backtrace.
    -fno-omit-frame-pointer)

target_link_libraries(
  ldd_enc_dep_1b
  PRIVATE
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    # Removed -Bsymbolic to trigger generation of relocations.
    # Removed -pie to create a shared library and instead used pic.
    -Wl,--no-undefined,-Bstatic,--export-dynamic,--build-id
    # Secondary modules are linked as position independent libraries (-pic) instead
    # of position independent executables (-pie).
    -Wl,-pic
    -Wl,-z,noexecstack
    -Wl,-z,now
    -Wl,-gc-sections)
