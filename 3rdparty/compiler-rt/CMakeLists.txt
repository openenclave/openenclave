# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(FetchContent)
FetchContent_Declare(
  compiler-rt-sources
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/compiler-rt
  URL https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.1/compiler-rt-10.0.1.src.tar.xz
  URL_HASH
    SHA256=d90dc8e121ca0271f0fd3d639d135bfaa4b6ed41e67bd6eb77808f72629658fa)

FetchContent_GetProperties(compiler-rt-sources)
if (NOT compiler-rt-sources_POPULATED)
  FetchContent_Populate(compiler-rt-sources)
endif ()

set(COMPILER_RT_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/compiler-rt/lib/builtins/")

# List based on compiler-rt/lib/builtins/CMakeLists.txt
set(GENERIC_SOURCES
    absvdi2.c
    absvsi2.c
    absvti2.c
    adddf3.c
    addsf3.c
    addtf3.c
    addvdi3.c
    addvsi3.c
    addvti3.c
    ashldi3.c
    ashlti3.c
    ashrdi3.c
    ashrti3.c
    bswapdi2.c
    bswapsi2.c
    clzdi2.c
    clzsi2.c
    clzti2.c
    cmpdi2.c
    cmpti2.c
    comparedf2.c
    comparesf2.c
    ctzdi2.c
    ctzsi2.c
    ctzti2.c
    divdc3.c
    divdf3.c
    divdi3.c
    divmoddi4.c
    divmodsi4.c
    divsc3.c
    divsf3.c
    divsi3.c
    divtc3.c
    divti3.c
    divtf3.c
    extendsfdf2.c
    extendhfsf2.c
    ffsdi2.c
    ffssi2.c
    ffsti2.c
    fixdfdi.c
    fixdfsi.c
    fixdfti.c
    fixsfdi.c
    fixsfsi.c
    fixsfti.c
    fixunsdfdi.c
    fixunsdfsi.c
    fixunsdfti.c
    fixunssfdi.c
    fixunssfsi.c
    fixunssfti.c
    floatdidf.c
    floatdisf.c
    floatsidf.c
    floatsisf.c
    floattidf.c
    floattisf.c
    floatundidf.c
    floatundisf.c
    floatunsidf.c
    floatunsisf.c
    floatuntidf.c
    floatuntisf.c
    fp_mode.c
    int_util.c
    lshrdi3.c
    lshrti3.c
    moddi3.c
    modsi3.c
    modti3.c
    muldc3.c
    muldf3.c
    muldi3.c
    mulodi4.c
    mulosi4.c
    muloti4.c
    mulsc3.c
    mulsf3.c
    multi3.c
    multf3.c
    mulvdi3.c
    mulvsi3.c
    mulvti3.c
    negdf2.c
    negdi2.c
    negsf2.c
    negti2.c
    negvdi2.c
    negvsi2.c
    negvti2.c
    os_version_check.c
    paritydi2.c
    paritysi2.c
    parityti2.c
    popcountdi2.c
    popcountsi2.c
    popcountti2.c
    powidf2.c
    powisf2.c
    powitf2.c
    subdf3.c
    subsf3.c
    subvdi3.c
    subvsi3.c
    subvti3.c
    subtf3.c
    trampoline_setup.c
    truncdfhf2.c
    truncdfsf2.c
    truncsfhf2.c
    ucmpdi2.c
    ucmpti2.c
    udivdi3.c
    udivmoddi4.c
    udivmodsi4.c
    udivmodti4.c
    udivsi3.c
    udivti3.c
    umoddi3.c
    umodsi3.c
    umodti3.c)

set(GENERIC_TF_SOURCES
    comparetf2.c
    extenddftf2.c
    extendsftf2.c
    fixtfdi.c
    fixtfsi.c
    fixtfti.c
    fixunstfdi.c
    fixunstfsi.c
    fixunstfti.c
    floatditf.c
    floatsitf.c
    floattitf.c
    floatunditf.c
    floatunsitf.c
    floatuntitf.c
    multc3.c
    trunctfdf2.c
    trunctfsf2.c)

# The following is commented out since OE uses a different unwinder and defines
# a void* personality.
# set(GENERIC_SOURCES ${GENERIC_SOURCES} gcc_personality_v0.c)
# Make unwind.h available.
# set_source_files_properties(${COMPILER_RT_SRC_DIR}/gcc_personality_v0.c
#  PROPERTIES
#   COMPILE_FLAGS "-I ${PROJECT_SOURCE_DIR}/3rdparty/libunwind/libunwind/include")

set(GENERIC_SOURCES ${GENERIC_SOURCES} clear_cache.c)

set(x86_ARCH_SOURCES
    cpu_model.c
    divxc3.c
    fixxfdi.c
    fixxfti.c
    fixunsxfdi.c
    fixunsxfsi.c
    fixunsxfti.c
    floatdixf.c
    floattixf.c
    floatundixf.c
    floatuntixf.c
    mulxc3.c
    powixf2.c)

set(x86_64_SOURCES
    x86_64/floatdidf.c x86_64/floatdisf.c x86_64/floatdixf.c
    x86_64/floatundidf.S x86_64/floatundisf.S x86_64/floatundixf.S)

set(x86_64_SOURCES ${GENERIC_TF_SOURCES} ${GENERIC_SOURCES} ${x86_64_SOURCES}
                   ${x86_ARCH_SOURCES})

set(aarch64_SOURCES ${GENERIC_TF_SOURCES} ${GENERIC_SOURCES} aarch64/fp_mode.c)

if (OE_SGX)
  set(SOURCES ${x86_64_SOURCES})
else ()
  set(SOURCES ${aarch64_SOURCES})
endif ()

list(TRANSFORM SOURCES PREPEND "${COMPILER_RT_SRC_DIR}")

add_enclave_library(oecompiler-rt OBJECT ${SOURCES})

maybe_build_using_clangw(oecompiler-rt)

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR USE_CLANGW)
  enclave_compile_options(
    oecompiler-rt
    PRIVATE
    -Wno-sign-conversion
    -Wno-unused-parameter
    -Wno-implicit-int-float-conversion
    -Wno-shorten-64-to-32
    -Wno-float-conversion
    -Wno-implicit-int-conversion
    -fno-stack-protector
    -std=c11
    -nostdinc
    -fno-omit-frame-pointer
    -fno-builtin
    -fpic
    -ffreestanding)
else ()
  enclave_compile_options(
    oecompiler-rt
    PRIVATE
    -Wno-conversion
    -Wno-builtin-declaration-mismatch
    -Wno-unused-parameter
    -fno-stack-protector
    -std=c11
    -nostdinc
    -fno-omit-frame-pointer
    -fno-builtin
    -fpic
    -ffreestanding)
endif ()

enclave_link_libraries(oecompiler-rt PRIVATE oelibc_includes)

install_enclaves(
  TARGETS
  oecompiler-rt
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

# Build gcov for code coverage
if (CODE_COVERAGE OR BUILD_LIBGCOV)
  apply_patches(patches compiler-rt)

  add_enclave_library(
    gcov
    STATIC
    # Only the following three files are required to support GCOV-based code coverage analysis.
    compiler-rt/lib/profile/GCDAProfiling.c
    compiler-rt/lib/profile/InstrProfiling.c
    compiler-rt/lib/profile/InstrProfilingUtil.c)

  maybe_build_using_clangw(gcov)

  enclave_compile_options(gcov PRIVATE -Wno-error)

  enclave_link_libraries(gcov PRIVATE oelibc oehostfs)

  enclave_include_directories(gcov PRIVATE src
                              ${CMAKE_CURRENT_SOURCE_DIR}/compiler-rt/include)

  install_enclaves(
    TARGETS
    gcov
    EXPORT
    openenclave-targets
    ARCHIVE
    DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

endif ()
