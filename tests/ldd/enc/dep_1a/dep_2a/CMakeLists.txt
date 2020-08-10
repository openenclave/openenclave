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
    # "The default without -fpic is 'initial-exec'; with -fpic the
    # default is 'global-dynamic'."
    # https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html#Code-Gen-Options
    #
    # Enclaves are linked using -pie and therefore global-dynamic is
    # too conservative. Of the two efficient static thread-local
    # storage models, inital-exec and local-exec, we choose the most
    # optimal one.
    -ftls-model=local-exec
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
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id
    -Wl,-z,noexecstack
    -Wl,-z,now
    -Wl,-gc-sections)
