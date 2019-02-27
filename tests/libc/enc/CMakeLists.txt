# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


# Include the libc tests wrappers:
include(../tests.cmake)

# Generate wrappers for libc tests.
foreach(test_file ${LIBC_TESTS})
  string(MAKE_C_IDENTIFIER ${test_file} test_name)
  list(APPEND test_dependencies ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
  configure_file(include.c.in ${test_file})
  string(APPEND run_test "\
    extern int ${test_name}(int argc, const char* argv[]);\n\
    ret += run_test(\"${test_name}\", ${test_name});\n")
endforeach()

configure_file(tests.c.in tests.c)

oeedl_file(../libc.edl enclave gen)

add_enclave(TARGET libc_enc
    SOURCES
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/tests.c
    ${test_dependencies}
    ../../../3rdparty/musl/libc-test/src/common/mtest.c
    ../../../3rdparty/musl/libc-test/src/common/rand.c
    ../../../3rdparty/musl/libc-test/src/functional/tls_align_dso.c
    ${LIBC_TESTS}
    ${gen})

target_compile_options(libc_enc PRIVATE
    -Wno-error
    -Wno-unknown-pragmas
    -Wno-unused-function
    -Wno-return-type
    -Wno-macro-redefined
    -Wno-unused-variable
    -Wno-literal-range
    -Wno-missing-braces
    -Wno-writable-strings
    -mfpmath=sse)

target_include_directories(
    libc_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    .
    ../../../3rdparty/musl/libc-test/src/common)

maybe_build_using_clangw(libc_enc)

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

target_link_libraries(libc_enc oelibc)
