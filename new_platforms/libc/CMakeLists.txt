if(NOT TZ)
    message(FATAL_ERROR "The custom C runtime library is only supported for Linux + ARM TrustZone.")
endif()

set(ARCH "aarch64")

# Override compiler inside TA's.
set(CMAKE_ASM_COMPILER ${OE_TA_TOOLCHAIN_PREFIX}gcc)
set(CMAKE_C_COMPILER   ${OE_TA_TOOLCHAIN_PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${OE_TA_TOOLCHAIN_PREFIX}g++)

# Path to Open Enclave proper.
set(OE_PATH ${CMAKE_CURRENT_LIST_DIR}/../..)
set(OE_INC  ${OE_PATH}/include)

# Path to the C runtime library (musl).
set(MUSL_OE      ${OE_PATH}/3rdparty/musl)
set(MUSL_PATCHES ${MUSL_OE}/patches)
set(MUSL_SRC     ${MUSL_OE}/musl)
set(MUSL_OUT     ${CMAKE_CURRENT_BINARY_DIR}/musl)
set(MUSL_OUT_INC ${MUSL_OUT}/include)
set(MUSL_CFLAGS  "-fPIC -DSYSCALL_NO_INLINE")

set(MUSL_OUT     ${MUSL_OUT}     PARENT_SCOPE)
set(MUSL_OUT_INC ${MUSL_OUT_INC} PARENT_SCOPE)

# Path to the memory allocated (dlmalloc).
set(DLMALLOC_OE  ${OE_PATH}/3rdparty/dlmalloc)
set(DLMALLOC_SRC ${DLMALLOC_OE}/dlmalloc)

# Path to OP-TEE OS.
set(OPTEE_SRC    ${OE_PATH}/3rdparty/optee_os)

# Path to OP-TEE's user-mode library (libutee).
set(LIBUTEE_SRC  ${OPTEE_SRC}/lib/libutee)
set(LIBUTEE_INC  ${LIBUTEE_SRC}/include)

# Path to OP-TEE's user-mode utilities (libutils).
set(LIBUTILS_SRC ${OPTEE_SRC}/lib/libutils)

# Path to OP-TEE's user-mode C runtime library (part of libutils).
set(LIBUTILS_ISOC_INC ${LIBUTILS_SRC}/isoc/include)

# Path to OP-TEE's user-mode C runtime library extenions (part of libutils).
set(LIBUTILS_EXT_SRC ${LIBUTILS_SRC}/ext)
set(LIBUTILS_EXT_INC ${LIBUTILS_EXT_SRC}/include)

# Path to OP-TEE's user-mode math library (libmpa).
set(LIBMPA_SRC   ${OPTEE_SRC}/lib/libmpa)
set(LIBMPA_INC   ${LIBMPA_SRC}/include)

# Path to the C++ runtime library (libcxx).
set(LIBCXX_OE      ${OE_PATH}/3rdparty/libcxx)
set(LIBCXX_SRC     ${LIBCXX_OE}/libcxx)
set(LIBCXX_OUT     ${CMAKE_CURRENT_BINARY_DIR}/libcxx)
set(LIBCXX_OUT_INC ${LIBCXX_OUT}/include)

# Path to the C++ ABI library (libcxxrt).
set(LIBCXXRT_OE  ${OE_PATH}/3rdparty/libcxxrt)
set(LIBCXXRT_SRC ${LIBCXXRT_OE}/libcxxrt)

# Path to the stack unwinding library (libunwind).
set(LIBUNWIND_OE  ${OE_PATH}/3rdparty/libunwind)
set(LIBUNWIND_SRC ${LIBUNWIND_OE}/libunwind)

# Source listings (uses the variables defined above).
include(${CMAKE_CURRENT_LIST_DIR}/libc.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/libcxx.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/libcxxrt.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/libunwind.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/libutee.cmake)

# Set up musl.
include(ExternalProject)
ExternalProject_Add(musl_includes
    DOWNLOAD_COMMAND
        ${CMAKE_COMMAND} -E copy_directory
        ${MUSL_SRC}
        ${MUSL_OUT}
    PATCH_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy
            ${MUSL_OUT}/arch/${ARCH}/syscall_arch.h
            ${MUSL_OUT}/arch/${ARCH}/__syscall_arch.h
        COMMAND ${CMAKE_COMMAND} -E copy
            ${MUSL_PATCHES}/syscall_arch.h
            ${MUSL_OUT}/arch/${ARCH}/syscall_arch.h
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_LIST_DIR}/enc/optee/patches/pthread_arch.h
            ${MUSL_OUT}/arch/${ARCH}/pthread_arch.h
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E chdir ${MUSL_OUT}
        sh -x ./configure
            --includedir=${MUSL_OUT_INC}
            CFLAGS=${MUSL_CFLAGS}
            CC=${CMAKE_C_COMPILER}
            CXX=${CMAKE_CXX_COMPILER}
    BUILD_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${MUSL_OUT}/include
            ${MUSL_OUT_INC}
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${MUSL_OUT}/arch/generic/bits
            ${MUSL_OUT_INC}/bits
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${MUSL_OUT}/arch/${ARCH}/bits
            ${MUSL_OUT_INC}/bits
        COMMAND sh -c
            "sed -f ${MUSL_OUT}/tools/mkalltypes.sed ${MUSL_OUT}/arch/${ARCH}/bits/alltypes.h.in ${MUSL_OUT}/include/alltypes.h.in > ${MUSL_OUT_INC}/bits/alltypes.h"
        COMMAND ${CMAKE_COMMAND} -E copy
            ${MUSL_OUT}/arch/${ARCH}/bits/syscall.h.in
            ${MUSL_OUT_INC}/bits/syscall.h
        COMMAND sh -c
            "sed -n -e s/__NR_/SYS_/p < ${MUSL_OUT}/arch/${ARCH}/bits/syscall.h.in >> ${MUSL_OUT_INC}/bits/syscall.h"
    BUILD_BYPRODUCTS
        ${MUSL_OUT_INC}
        ${MUSL_OUT}
    INSTALL_COMMAND "")

# Set up C runtime library.
add_library(libcasm OBJECT ${LIBC_S_SRC})
add_dependencies(libcasm musl_includes)
target_compile_options(libcasm PRIVATE ${OE_TA_S_FLAGS})

add_library(libc OBJECT ${LIBC_C_SRC})
set_property(TARGET libc PROPERTY C_STANDARD 99)
target_compile_options(libc
    PRIVATE -fexcess-precision=standard -frounding-math
    PUBLIC ${OE_TA_C_FLAGS})
target_include_directories(libc
    PRIVATE ${MUSL_OUT}/src/include
    PRIVATE ${MUSL_OUT}/src/internal
    PRIVATE ${MUSL_OUT}/arch/${ARCH}
    PUBLIC ${MUSL_OUT_INC})
set_source_files_properties(${DLMALLOC_SRC}/malloc.c PROPERTIES COMPILE_FLAGS ${LIBC_MALLOC_FLAGS})

target_link_libraries(libc PUBLIC libcasm)

# Set up libutee.
add_library(libuteeasm OBJECT ${LIBUTEE_S_SRC})
set_property(TARGET libuteeasm PROPERTY C_STANDARD 99)
target_compile_options(libuteeasm PRIVATE
    ${OE_TA_S_FLAGS}
    -include ${OE_TA_DEV_KIT_CONF})
target_include_directories(libuteeasm PRIVATE
    ${LIBUTEE_INC}
    ${LIBUTILS_EXT_INC})

add_library(libutee OBJECT ${LIBUTEE_C_SRC})
set_property(TARGET libutee PROPERTY C_STANDARD 99)
target_compile_options(libutee PUBLIC
    -include ${OE_TA_DEV_KIT_CONF})
target_include_directories(libutee
    PRIVATE ${LIBUTEE_SRC}
    PUBLIC  ${LIBUTEE_INC}
    PUBLIC  ${LIBUTILS_EXT_INC}
    PRIVATE ${LIBUTILS_ISOC_INC}
    PRIVATE ${LIBMPA_INC})
target_link_libraries(libutee PUBLIC
    libuteeasm
    libc)

# Set up libunwind.
configure_file(
    ${LIBUNWIND_SRC}/include/libunwind-${ARCH}.h
    libunwind.h
    COPYONLY)
file(GENERATE OUTPUT config.h CONTENT "/* Empty file */\n")

set(PKG_MAJOR 1)
set(PKG_MINOR 3)
configure_file(
    ${LIBUNWIND_SRC}/include/libunwind-common.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/libunwind-common.inc
    COPYONLY)

file(COPY ${LIBUNWIND_SRC}/include/tdep-${ARCH}/
    DESTINATION tdep)

add_library(libunwind OBJECT ${LIBUNWIND_C_SRC})
target_compile_options(libunwind PRIVATE
    -DHAVE_ELF_H
    -DHAVE_ENDIAN_H
    -DHAVE_LINK_H
    -D_GNU_SOURCE
    -DPACKAGE_STRING=\"libunwind-1.3\"
    -DPACKAGE_BUGREPORT=\"unwind.org\"
    -include ${LIBUNWIND_OE}/stubs.h)
target_include_directories(libunwind PRIVATE
    ${OE_INC}
    ${LIBUNWIND_OE}
    ${LIBUNWIND_SRC}/include
    ${LIBUNWIND_SRC}/src/${ARCH}
    ${LIBUNWIND_SRC}/src
    ${CMAKE_CURRENT_BINARY_DIR}/tdep
    ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(libunwind PUBLIC libc)
set_target_properties(libunwind PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Set up libcxxrt.
add_library(libcxxrt OBJECT ${LIBCXXRT_CXX_SRC})
add_dependencies(libcxxrt musl_includes)
target_link_libraries(libcxxrt PUBLIC libunwind)
set_target_properties(libcxxrt PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_source_files_properties(${LIBCXXRT_SRC}/src/dynamic_cast.cc PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter")
set_source_files_properties(${LIBCXXRT_SRC}/src/exception.cc PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter -Wno-shift-negative-value -Wno-missing-field-initializers")
set_source_files_properties(${LIBCXXRT_SRC}/src/stdexcept.cc PROPERTIES COMPILE_FLAGS "-Wno-extra")
set_source_files_properties(${LIBCXXRT_SRC}/src/typeinfo.cc PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter")

# Set up libcxx.
include (ExternalProject)
ExternalProject_Add(libcxx_includes
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${LIBCXX_SRC}/include ${LIBCXX_OUT_INC}
        COMMAND ${CMAKE_COMMAND} -E copy
            ${LIBCXX_SRC}/include/__config
            ${LIBCXX_OUT_INC}/__config_original
        COMMAND ${CMAKE_COMMAND} -E copy
            ${LIBCXX_OE}/__config
            ${LIBCXX_OUT_INC}/__config
    INSTALL_COMMAND "")

add_library(libcxx OBJECT ${LIBCXX_CXX_SRC})
add_dependencies(libcxx libcxx_includes)
target_compile_options(libcxx PRIVATE
    -DLIBCXXRT
    -D_LIBCPP_PROVIDES_DEFAULT_RUNE_TABLE
    -D_LIBCPP_BUILDING_LIBRARY
    -D_LIBCPP_HAS_NO_CXX14_CONSTEXPR)
target_include_directories(libcxx BEFORE
    PUBLIC ${LIBCXX_OUT_INC}
    PRIVATE ${LIBCXX_SRC}/src
    PRIVATE ${LIBCXXRT_SRC}/src)
target_link_libraries(libcxx PUBLIC libcxxrt)
set_target_properties(libcxx PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_source_files_properties(${LIBCXX_SRC}/src/new.cpp PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter")
set_source_files_properties(${LIBCXX_SRC}/src/system_error.cpp PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter")

# Set up umbrella libraries
add_library(oelibc STATIC)
target_link_libraries(oelibc PUBLIC libc libutee libuteeasm gcc)

add_library(oelibcxx STATIC)
target_link_libraries(oelibcxx PUBLIC libcxx libcxxrt libunwind)
