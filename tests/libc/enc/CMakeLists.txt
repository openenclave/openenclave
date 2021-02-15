# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Include the libc tests wrappers:
include(../tests.cmake)

# Generate wrappers for libc tests.
foreach (test_file ${LIBC_TESTS})
  string(MAKE_C_IDENTIFIER ${test_file} test_name)
  list(APPEND test_dependencies ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
  configure_file(include.c.in ${test_file})

  string(APPEND forward_declarations
         "extern int ${test_name}(int argc, const char* argv[]);\n")
  string(APPEND test_table "{ \"${test_name}\", ${test_name} },\n")
endforeach ()

configure_file(libc_tests.h.in libc_tests.h)

set(EDL_FILE ../libc.edl)

add_custom_command(
  OUTPUT libc_t.h libc_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(test_extras
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common/vmfill.c
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common/mtest.c
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common/rand.c)

if (NOT OE_TRUSTZONE)
  # This file requires TLS relocations, which cannot be applied by OP-TEE's
  # ELF loader.
  list(
    APPEND test_extras
    ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/functional/tls_align_dso.c
  )
endif ()

add_enclave(
  TARGET
  libc_enc
  UUID
  d7fe296a-24e9-46d1-aa78-9c7395082a41
  # Building the enclave by default when enabling LVI mitigation to
  # test linking against LVI-mitigated libraries.
  ADD_LVI_MITIGATION
  SOURCES
  enc.c
  ${test_dependencies}
  ${test_extras}
  ${LIBC_TESTS}
  libc_t.c)

enclave_compile_options(
  libc_enc
  PRIVATE
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

if (CODE_COVERAGE)
  enclave_compile_definitions(libc_enc PRIVATE CODE_COVERAGE)
endif ()

if (OE_SGX)
  enclave_compile_options(libc_enc PRIVATE -Wno-macro-redefined
                          -Wno-literal-range -Wno-writable-strings)
elseif (OE_TRUSTZONE)
  enclave_compile_options(libc_enc PRIVATE -Wno-bool-compare)
endif ()

enclave_include_directories(
  libc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common)

# The following variables remain uninitialized on Linux and throw warnings
# Calling the function maybe_build_using_clangw(libc_enc) skips setting
# the following variables on linux and returns noop
set(CMAKE_C_CREATE_STATIC_LIBRARY "")
set(CMAKE_CXX_CREATE_STATIC_LIBRARY "")
set(CMAKE_C_STANDARD_LIBRARIES "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")

maybe_build_using_clangw(libc_enc)

# maybe_build_using_clangw populates variables in its parent scope (ie current scope)
# Propagate these variables back up to the caller.

# Propagate library names variables
set(CMAKE_STATIC_LIBRARY_PREFIX
    "${CMAKE_STATIC_LIBRARY_PREFIX}"
    PARENT_SCOPE)
set(CMAKE_STATIC_LIBRARY_SUFFIX
    "${CMAKE_STATIC_LIBRARY_SUFFIX}"
    PARENT_SCOPE)

# Propagate library tool variables
set(CMAKE_C_CREATE_STATIC_LIBRARY
    "${CMAKE_C_CREATE_STATIC_LIBRARY}"
    PARENT_SCOPE)
set(CMAKE_CXX_CREATE_STATIC_LIBRARY
    "${CMAKE_CXX_CREATE_STATIC_LIBRARY}"
    PARENT_SCOPE)

# Propagate linker variables
set(CMAKE_EXECUTABLE_SUFFIX
    "${CMAKE_EXECUTABLE_SUFFIX}"
    PARENT_SCOPE)
set(CMAKE_C_STANDARD_LIBRARIES
    "${CMAKE_C_STANDARD_LIBRARIES}"
    PARENT_SCOPE)
set(CMAKE_C_LINK_EXECUTABLE
    "${CMAKE_C_LINK_EXECUTABLE}"
    PARENT_SCOPE)
set(CMAKE_CXX_STANDARD_LIBRARIES
    "${CMAKE_CXX_STANDARD_LIBRARIES}"
    PARENT_SCOPE)
set(CMAKE_CXX_LINK_EXECUTABLE
    "${CMAKE_CXX_LINK_EXECUTABLE}"
    PARENT_SCOPE)

# Propagate cpmpiler variables
set(CMAKE_C_COMPILE_OBJECT
    "${CMAKE_C_COMPILE_OBJECT}"
    PARENT_SCOPE)
set(CMAKE_CXX_COMPILE_OBJECT
    "${CMAKE_CXX_COMPILE_OBJECT}"
    PARENT_SCOPE)

enclave_link_libraries(libc_enc oelibc oesyscall oehostresolver oehostfs
                       oehostsock)
