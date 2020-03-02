# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## These rules generate the edge routines for the internal TEE-agnostic
## ECALLs/OCALLs used by liboehost/liboecore.
##
##==============================================================================

set(EDL_DIR ${CMAKE_SOURCE_DIR}/common)

set(TEE_EDL_FILE ${EDL_DIR}/tee.edl)

add_custom_command(
    OUTPUT tee_t.h tee_t.c tee_args.h
    DEPENDS ${TEE_EDL_FILE} edger8r
    COMMAND edger8r --search-path ${EDL_DIR} --trusted ${TEE_EDL_FILE})

add_custom_target(tee_trusted_edl
    DEPENDS tee_t.h tee_t.c tee_args.h)

##==============================================================================
##
## These rules generate the edge routines for the internal ECALLs/OCALLs used
## by switchless calls.
##
##==============================================================================
if (OE_SGX)
    set(SWITCHLESS_EDL_FILE ${EDL_DIR}/sgx/switchless.edl)

    add_custom_command(
        OUTPUT switchless_t.h switchless_t.c switchless_args.h
        DEPENDS ${SWITCHLESS_EDL_FILE} edger8r
        COMMAND edger8r --search-path ${EDL_DIR} --trusted ${SWITCHLESS_EDL_FILE})

    add_custom_target(switchless_trusted_edl
        DEPENDS switchless_t.h switchless_t.c switchless_args.h)
endif()

##==============================================================================
##
## These rules generate the edge routines for the internal SGX-specific
## ECALLs/OCALLs used by liboehost/liboecore.
##
##==============================================================================

if(OE_SGX)
    set(SGX_EDL_FILE ${EDL_DIR}/sgx/sgx.edl)

    add_custom_command(
        OUTPUT sgx_t.h sgx_t.c sgx_args.h
        DEPENDS ${SGX_EDL_FILE} edger8r
        COMMAND edger8r --search-path ${EDL_DIR} --trusted ${SGX_EDL_FILE})

    add_custom_target(sgx_trusted_edl
        DEPENDS sgx_t.h sgx_t.c sgx_args.h)
endif()

##==============================================================================
##
## These rules build the oecore target.
##
##==============================================================================

set(PLATFORM_SRC "")
set(MUSL_SRC_DIR ${PROJECT_SOURCE_DIR}/3rdparty/musl/musl/src)

if (OE_SGX)
    list(APPEND PLATFORM_SRC
        ../../common/sgx/endorsements.c
        sgx/backtrace.c
        sgx/calls.c
        sgx/cpuid.c
        sgx/enter.S
        sgx/entropy.c
        sgx/exception.c
        sgx/exit.S
        sgx/getkey.S
        sgx/globals.c
        sgx/hostcalls.c
        sgx/init.c
        sgx/keys.c
        sgx/longjmp.S
        sgx/memory.c
        sgx/properties.c
        sgx/random_internal.c
        sgx/report.c
        sgx/sched_yield.c
        sgx/setjmp.S
        sgx/sgx_t_wrapper.c
        sgx/spinlock.c
        sgx/switchless_t_wrapper.c
        sgx/switchlesscalls.c
        sgx/td.c
        sgx/td_basic.c
        sgx/thread.c
        sgx/tracee.c)

    # Functions in td_basic.c will change the status of td and may trigger
    # stack check fail, thus it is necessary to turn off stack check.
    set_source_files_properties(sgx/td_basic.c PROPERTIES
        COMPILE_FLAGS -fno-stack-protector)

    # OS specific sources for SGX.
    if (UNIX OR USE_CLANGW)
        list(APPEND PLATFORM_SRC
            ../../common/sgx/rand.S
            sgx/linux/reloc.c
            sgx/linux/threadlocal.c)
    elseif (WIN32)
        list(APPEND PLATFORM_SRC
            ../../common/sgx/rand.asm
            sgx/windows/reloc.c)
    endif()
elseif (OE_TRUSTZONE)
    list(APPEND PLATFORM_SRC
        optee/backtrace.c
        optee/bounds.c
        optee/calls.c
        optee/entropy.c
        optee/header.c
        optee/hostcalls.c
        optee/globals.c
        optee/gp.c
        optee/keys.c
        optee/printf.c
        optee/random_internal.c
        optee/sched_yield.c
        optee/spinlock.c
        optee/stubs.c
        optee/thread.c
        optee/tracee.c)
endif()

if (OE_TRUSTZONE OR (OE_SGX AND (UNIX OR USE_CLANGW)))
    list(APPEND PLATFORM_SRC init_fini.c)
endif ()

add_library(oecore STATIC
    ../../common/safecrt.c
    ../../common/argv.c
    ${MUSL_SRC_DIR}/prng/rand.c
    ${MUSL_SRC_DIR}/string/memcmp.c
    ${MUSL_SRC_DIR}/string/memcpy.c
    ${MUSL_SRC_DIR}/string/memmove.c
    ${MUSL_SRC_DIR}/string/memset.c
    __secs_to_tm.c
    __stack_chk_fail.c
    arena.c
    assert.c
    atexit.c
    backtrace.c
    calls.c
    ctype.c
    debugmalloc.c
    errno.c
    gmtime.c
    hexdump.c
    hostcalls.c
    intstr.c
    malloc.c
    once.c
    printf.c
    pthread.c
    random.c
    result.c
    sbrk.c
    stdio.c
    strerror.c
    string.c
    strtok_r.c
    strtoul.c
    tee_t_wrapper.c
    time.c
    tracee.c
    ${PLATFORM_SRC})

# Suppress type conversion warnings introduced by 3rdparty code
set_source_files_properties(${MUSL_SRC_DIR}/prng/rand.c ROPERTIES
    COMPILE_FLAGS -Wno-conversion)
set_source_files_properties(${MUSL_SRC_DIR}/string/memmove.c PROPERTIES
    COMPILE_FLAGS -Wno-sign-conversion)
set_source_files_properties(${MUSL_SRC_DIR}/string/memset.c PROPERTIES
    COMPILE_FLAGS -Wno-conversion)
set_source_files_properties(__secs_to_tm.c PROPERTIES
    COMPILE_FLAGS -Wno-conversion)

maybe_build_using_clangw(oecore)

add_dependencies(oecore tee_trusted_edl)
if(OE_SGX)
    add_dependencies(oecore sgx_trusted_edl switchless_trusted_edl)
endif()
target_include_directories(oecore PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oecore PUBLIC oe_includes)
if (OE_TRUSTZONE)
    target_link_libraries(oecore PUBLIC oelibutee_includes)
endif ()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(oecore PRIVATE -Wjump-misses-init)
endif()

# This directory contains enclave core libc headers:
target_include_directories(oecore PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

# Unfortunately dlmalloc uses GNU extension that allows arithmetic
# null pointers.
set_source_files_properties(malloc.c
    PROPERTIES COMPILE_FLAGS "-Wno-conversion -Wno-null-pointer-arithmetic")

if (OE_SGX)
    set_source_files_properties(sgx/keys.c PROPERTIES COMPILE_FLAGS -Wno-type-limits)

    # -m64 is an x86_64 specific flag
    target_compile_options(oecore PUBLIC -m64)
endif()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
    target_compile_options(oecore PRIVATE -Wjump-misses-init)
endif ()

# NOTE: All code inside an enclave must be compile with "position
# independent executable" semantics via -fPIE, and linked with -pie.
# Hence the PUBLIC (and INTERFACE) use of these flags instead of -fPIC
# or POSITION_INDEPENDENT_CODE, which would use the incorrect flag as
# enclaves actually are executables.
if (OE_SGX)
    target_compile_options(oecore PUBLIC
        -fPIE
        -nostdinc
        -fstack-protector-strong
        -fvisibility=hidden
        # Preserve frame-pointer in Release mode to enable oe_backtrace.
        -fno-omit-frame-pointer
        # Put each function or data in its own section.
        # This allows aggressively eliminating unused code.
        -ffunction-sections -fdata-sections
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
        $<BUILD_INTERFACE:-fno-builtin-malloc -fno-builtin-calloc -fno-builtin>)
elseif (OE_TRUSTZONE)
    target_compile_options(oecore PUBLIC
        -fvisibility=hidden
        ${OE_TZ_TA_C_FLAGS})
endif()

target_compile_options(oecore INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)

target_compile_definitions(oecore
    PUBLIC
    OE_BUILD_ENCLAVE
    # NOTE: This definition is public to the rest of our project's
    # targets, but should not yet be exposed to consumers of our
    # package.
    $<BUILD_INTERFACE:OE_API_VERSION=2>)

if(HAS_QUOTE_PROVIDER)
    target_compile_definitions(oecore PUBLIC OE_LINK_SGX_DCAP_QL)
endif()

if(USE_DEBUG_MALLOC)
    target_compile_definitions(oecore PRIVATE OE_USE_DEBUG_MALLOC)
    message("USE_DEBUG_MALLOC is set, building oecore with memory leak detection.")
endif()

# Interface link flags for enclaves.
if(OE_SGX)
    target_link_libraries(oecore INTERFACE
        -nostdlib -nodefaultlibs -nostartfiles
        -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id
        -Wl,-z,noexecstack
        -Wl,-z,now
        -Wl,-gc-sections)
elseif(OE_TRUSTZONE)
    target_link_libraries(oecore INTERFACE
        -nostdlib -nodefaultlibs -nostartfiles
        --no-undefined
        -pie
        --sort-section=alignment
        "-z max-page-size=4096"
        --as-needed)
endif()

set_property(TARGET oecore PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oecore EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
