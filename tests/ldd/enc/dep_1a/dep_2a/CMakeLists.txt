# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Build enclave shared object dependency
set(LDD_TEST_DEP_SUFFIX 2a)
set(LDD_TEST_DEP_MAGIC 2001)
configure_file(${CMAKE_SOURCE_DIR}/tests/ldd/enc/dep_common.c.in dep_common.c)

add_library(ldd_enc_dep_2a SHARED dep_common.c)
set_target_properties(ldd_enc_dep_2a PROPERTIES LIBRARY_OUTPUT_DIRECTORY
                                                ${LDD_TEST_ENC_DIR})
target_include_directories(ldd_enc_dep_2a PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(
  ldd_enc_dep_2a
  PUBLIC
    -fPIC
    -nostdinc
    -fstack-protector-strong
    # Preserve frame-pointer in Release mode to enable oe_backtrace.
    -fno-omit-frame-pointer
    # Put each function or data in its own section.
    # This allows aggressively eliminating unused code.
    -ffunction-sections
    -fdata-sections
    # The secondary modules are compiled with -ftls-model=initial-exec flag.
    # This informs the compiler that the modules will be loaded along with the main module,
    # rather than being dynamically loaded via dlopen. In this case, the compiler
    # will generate R_X86_64_TPOFF relocations for thread-local variables.
    -ftls-model=initial-exec
    # Disable builtin functions for enclaves, but only in our build.
    #
    # We do this to work-around compiler bugs (see #1429) due to our
    # redefinition of `memmove` to `oe_memmove` causing an undefined
    # symbol error when a built-in was inlined. However, we only do
    # this for our code as we don't want to force these flags on the
    # user. There are valid reasons for an end user to use built-ins.
    $<BUILD_INTERFACE:-fno-builtin-malloc
    -fno-builtin-calloc
    -fno-builtin>)

target_link_libraries(
  ldd_enc_dep_2a
  PRIVATE
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,--build-id
    # Secondary modules are linked as position independent libraries (-pic) instead
    # of position independent executables (-pie).
    -Wl,-pic
    -Wl,-z,noexecstack
    -Wl,-z,now
    -Wl,-gc-sections)
