# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Create a custom command to workaround a likely cmake dependency bug.
# See 3rdparty/snmalloc/CMakeLists.txt for explanation of the issue
# and the workaround.
add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/deprecations.h
         ${CMAKE_CURRENT_BINARY_DIR}/__config.h
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${PROJECT_BINARY_DIR}/output/include/openenclave/libc/bits/deprecations.h
    ${CMAKE_CURRENT_BINARY_DIR}/deprecations.h
  DEPENDS musl_includes)

add_enclave_library(
  oecompilerrt_obj
  OBJECT
  # List the following as a source in order to ensure that musl_includes is
  # built before the build for oecompilerrt_obj is started.
  # started.
  deprecations.h
  # compiler-rt implementation.
  compiler-rt/addtf3.c
  compiler-rt/ashldi3.c
  compiler-rt/ashlti3.c
  compiler-rt/ashrdi3.c
  compiler-rt/ashrti3.c
  compiler-rt/clear_cache.c
  compiler-rt/clzdi2.c
  compiler-rt/clzsi2.c
  compiler-rt/clzti2.c
  compiler-rt/cmpdi2.c
  compiler-rt/cmpti2.c
  compiler-rt/comparetf2.c
  compiler-rt/ctzdi2.c
  compiler-rt/ctzsi2.c
  compiler-rt/ctzti2.c
  compiler-rt/divdi3.c
  compiler-rt/divsi3.c
  compiler-rt/divtf3.c
  compiler-rt/divti3.c
  compiler-rt/extenddftf2.c
  compiler-rt/extendsftf2.c
  compiler-rt/ffsdi2.c
  compiler-rt/ffsti2.c
  compiler-rt/fixtfsi.c
  compiler-rt/floatsitf.c
  compiler-rt/floatunsitf.c
  compiler-rt/lshrdi3.c
  compiler-rt/lshrti3.c
  compiler-rt/moddi3.c
  compiler-rt/modsi3.c
  compiler-rt/modti3.c
  compiler-rt/muldi3.c
  compiler-rt/multf3.c
  compiler-rt/multi3.c
  compiler-rt/negdi2.c
  compiler-rt/negti2.c
  compiler-rt/paritydi2.c
  compiler-rt/paritysi2.c
  compiler-rt/parityti2.c
  compiler-rt/popcountdi2.c
  compiler-rt/popcountsi2.c
  compiler-rt/popcountti2.c
  # OE has a custom implementation of stack protector that works
  # within enclaves.
  # compiler-rt/stack_chk.c
  compiler-rt/subtf3.c
  compiler-rt/trunctfdf2.c
  compiler-rt/trunctfsf2.c
  compiler-rt/ucmpdi2.c
  compiler-rt/ucmpti2.c
  compiler-rt/udivdi3.c
  compiler-rt/udivmoddi4.c
  compiler-rt/udivmodti4.c
  compiler-rt/udivsi3.c
  compiler-rt/udivti3.c
  compiler-rt/umoddi3.c
  compiler-rt/umodsi3.c
  compiler-rt/umodti3.c)

if (OE_TRUSTZONE)
  set(TEE_C_FLAGS ${OE_TZ_TA_C_FLAGS})
else ()
  set(TEE_C_FLAGS -mcx16)
endif ()

enclave_compile_options(
  oecompilerrt_obj
  PRIVATE
  # compiler-rt depends on C headers
  -I${PROJECT_BINARY_DIR}/output/include/openenclave/libc
  # Prevent warnings treated as errors
  -Wno-conversion
  -Wno-unused-parameter
  # Enclave compiler options
  -ftls-model=local-exec
  -nostdinc
  -fPIE
  -ffreestanding
  ${TEE_C_FLAGS}
  -fno-exceptions
  -fvisibility=hidden)

maybe_build_using_clangw(oecompilerrt_obj)

install_enclaves(
  TARGETS
  oecompilerrt_obj
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
