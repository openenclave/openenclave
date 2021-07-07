# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Overwrite the default setting such that the library is generated under the
# same directory as the enclave binary
if (UNIX)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/../enc)
elseif (WIN32)
  # On Windows, use RUNTIME_OUTPUT_DIRECTORY instead
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/../enc)
endif ()

add_enclave_library(module SHARED module.c)

maybe_build_using_clangw(module)

# Use OE's default flags for enclaves
enclave_compile_options(
  module
  PUBLIC
  -fPIC
  -nostdinc
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

add_enclave_dependencies(module oelibc_includes)

enclave_include_directories(module PRIVATE ${OE_INCDIR}/openenclave/libc)

enclave_link_libraries(
  module
  PRIVATE
  -nostdlib
  -nodefaultlibs
  -Wl,-z,noexecstack
  -Wl,-z,now
  -Wl,-gc-sections)
