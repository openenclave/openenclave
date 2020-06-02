# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Create a binary for each testcase listed in ../tests.supported
# These tests generate a large number of warnings, some of them specific to compiler versions.
# Disabling warning-as-errors for the specific warnings is painful across multiple different compilers.
# It was agreed to, that it is best to just disable warnings-as-errors for these tests specifically.

set(EDL_FILE ../libunwind.edl)

add_custom_command(
  OUTPUT libunwind_t.h libunwind_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(LIBUNWIND_TEST_DIR ${PROJECT_SOURCE_DIR}/3rdparty/libunwind/libunwind/tests)

# helper lib to contain file needed by some tests
add_enclave_library(
  libunwindtest-support
  ${LIBUNWIND_TEST_DIR}/ident.c
  ${LIBUNWIND_TEST_DIR}/flush-cache.S
  ${LIBUNWIND_TEST_DIR}/test-static-link-gen.c
  ${LIBUNWIND_TEST_DIR}/flush-cache.h
  test_support.c)
enclave_link_libraries(libunwindtest-support PRIVATE oeenclave oelibc)
enclave_compile_options(libunwindtest-support PRIVATE -Wno-error
                        -DUNW_LOCAL_ONLY=1)
enclave_include_directories(
  libunwindtest-support PUBLIC ${PROJECT_SOURCE_DIR}/3rdparty/libunwind
  ${PROJECT_BINARY_DIR}/3rdparty/libunwind
  ${PROJECT_SOURCE_DIR}/3rdparty/libunwind/libunwind/include)

function (add_libunwind_test_enc NAME TESTFILE)
  add_enclave(
    TARGET
    libunwindtest-${NAME}_enc
    UUID
    061c1ea0-22b3-4194-a8cd-44242462f22a
    CXX
    SOURCES
    enc.c
    libunwind_t.c
    ${PROJECT_SOURCE_DIR}/${TESTFILE})
  enclave_include_directories(
    libunwindtest-${NAME}_enc PRIVATE ..
    ${PROJECT_BINARY_DIR}/3rdparty/libunwind/libunwind/tests
    ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
  enclave_compile_options(
    libunwindtest-${NAME}_enc
    PRIVATE
    -Wno-error
    -Wno-macro-redefined # We need `UNW_LOCAL_ONLY=1` but some files already define it.
    -fno-inline-functions)
  if (("${NAME}" STREQUAL "Ltest-varargs") AND ("${CMAKE_CXX_COMPILER_ID}"
                                                MATCHES "Clang"))
    enclave_compile_options(libunwindtest-${NAME}_enc PRIVATE -include
                            enc/clang_varargs_extra.h)
  endif ()
  enclave_compile_definitions(libunwindtest-${NAME}_enc PRIVATE -DWITH_MAIN
                              -D__TEST__="${TESTFILE}" -DUNW_LOCAL_ONLY=1)
  enclave_link_libraries(libunwindtest-${NAME}_enc libunwindtest-support)
  enclave_link_libraries(libunwindtest-${NAME}_enc
                         -Wl,--undefined=pthread_mutex_lock)
  enclave_link_libraries(libunwindtest-${NAME}_enc
                         -Wl,--undefined=_U_dyn_info_list_addr)

  if (WIN32)
    maybe_build_using_clangw(libunwindtest-${NAME}_enc)

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
  endif ()
endfunction (add_libunwind_test_enc)

file(STRINGS "../tests.supported" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "3rdparty/libunwind/libunwind/tests/")
  add_libunwind_test_enc("${name}" "${testcase}")
endforeach (testcase)
