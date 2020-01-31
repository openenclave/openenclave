# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


# Include the libc tests wrappers:
include(../tests.cmake)

set (EDL_FILE ../libc.edl)

add_custom_command(
    OUTPUT libc_t.h libc_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(test_extras
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common/vmfill.c
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common/mtest.c
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common/rand.c)

if(NOT OE_TRUSTZONE)
    # This file requires TLS relocations, which cannot be applied by OP-TEE's
    # ELF loader.
    list(APPEND test_extras
        ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/functional/tls_align_dso.c)
endif()

set(LIBC_COMPILE_OPTIONS
    -Wno-error
    -Wno-unknown-pragmas
    -Wno-unused-function
    -Wno-return-type
    -Wno-unused-variable
    -Wno-missing-braces
    -Wno-unused-parameter
    -Wno-float-conversion
    -Wno-sign-conversion
    -Wno-sign-compare
    -Wno-conversion
    -Wno-parentheses
    -Wno-unused-value
    -Wno-overflow)

if(OE_SGX)
    list(APPEND LIBC_COMPILE_OPTIONS
        -Wno-macro-redefined
        -Wno-literal-range
        -Wno-writable-strings)
elseif(OE_TRUSTZONE)
    list(APPEND LIBC_COMPILE_OPTIONS -Wno-bool-compare)
endif()

set (LIBC_INCLUDE_DIRECTORIES
    ${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common)


add_library(libctest-support
    enc.c
    helpers.c
    libc_t.c
    ${test_extras})

target_include_directories(libctest-support PRIVATE ${LIBC_INCLUDE_DIRECTORIES})
target_link_libraries(libctest-support PRIVATE oecore)
target_link_libraries(libctest-support PRIVATE oelibc)
target_compile_options(libctest-support PRIVATE ${LIBC_COMPILE_OPTIONS})

set (LIBC_ENC_REQUIRED_LIBRARIES
    libctest-support
    oelibc
    oesyscall
    oehostresolver
    oehostfs
    oehostsock)

# A function for compiling a single libc test in its own enclave binary.
# This is only used when libc tests are run individually by defining
# SEPERATE_LIBC_TESTS=TRUE
function(add_libc_test_enc NAME CFILE)
    # Generate a new uuid per enclave for trustzone
    string(UUID enclave_uuid
           NAMESPACE "d7fe296a-24e9-46d1-aa78-9c7395082a41"
           NAME libc-${NAME}_enc
           TYPE SHA1)

    add_enclave(TARGET libc-${NAME}_enc UUID ${enclave_uuid} SOURCES
        ${PROJECT_SOURCE_DIR}/${CFILE}
        run_tests_single.c
        libc_t.c)

    # add_enclave modifies CMAKE_C_LINK_EXECUTABLE, CMAKE_CXX_LINK_EXECUTABLE,
    # and CMAKE_EXE_LINKER_FLAGS. Propogate them to the parent scope
    set(CMAKE_C_LINK_EXECUTABLE ${CMAKE_C_LINK_EXECUTABLE} PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE ${CMAKE_CXX_LINK_EXECUTABLE} PARENT_SCOPE)
    set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} PARENT_SCOPE)

    target_compile_options(libc-${NAME}_enc PRIVATE ${LIBC_COMPILE_OPTIONS} -D__TEST__="${NAME}")
    target_include_directories(libc-${NAME}_enc PRIVATE ${LIBC_INCLUDE_DIRECTORIES})
    target_link_libraries(libc-${NAME}_enc ${LIBC_ENC_REQUIRED_LIBRARIES})
endfunction(add_libc_test_enc)

if (OE_SEPARATE_LIBC_TESTS)
    foreach (test_file ${LIBC_TESTS})
        get_testcase_name(${test_file} name "../../")
        add_libc_test_enc("${name}" "${test_file}")
    endforeach ()
else ()
    foreach (test_file ${LIBC_TESTS})
        string(MAKE_C_IDENTIFIER ${test_file} test_name)
        configure_file(include.c.in ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
        list(APPEND test_dependencies ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
        string(APPEND libc_tests "\
        extern int ${test_name}(int argc, const char* argv[]);\n\
        ret += run_single_test(\"${test_name}\", ${test_name});\n")
    endforeach ()

    configure_file(run_tests_all.c.in run_tests_all.c)
    add_enclave(TARGET libc_enc UUID d7fe296a-24e9-46d1-aa78-9c7395082a41 SOURCES
        ${CMAKE_CURRENT_BINARY_DIR}/run_tests_all.c
        ${test_dependencies}
        libc_t.c)

    target_compile_options(libc_enc PRIVATE ${LIBC_COMPILE_OPTIONS})
    target_include_directories(libc_enc PRIVATE ${LIBC_INCLUDE_DIRECTORIES})
    target_link_libraries(libc_enc ${LIBC_ENC_REQUIRED_LIBRARIES})
endif ()

# On windows, build the enclave support library with clangw
if (WIN32)
    maybe_build_using_clangw(libunwindtest-${NAME}_enc)

    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX "${CMAKE_STATIC_LIBRARY_PREFIX}" PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}" PARENT_SCOPE)

    # Propagate library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY "${CMAKE_C_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY "${CMAKE_CXX_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)

    # Propagate linker variables
    set(CMAKE_EXECUTABLE_SUFFIX "${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES}" PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE}" PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES}" PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE}" PARENT_SCOPE)

    # Propagate cpmpiler variables
    set(CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}" PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}" PARENT_SCOPE)
endif ()
