# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Create a binary for each testcase listed in ../tests.supported
# These tests generate a large number of warnings, some of them specific to compiler versions.
# Disabling warning-as-errors for the specific warnings is painful across multiple different compilers.
# It was agreed to, that it is best to just disable warnings-as-errors for these tests specifically.

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

set(LIBUNWIND_TEST_DIR ${PROJECT_SOURCE_DIR}/3rdparty/libunwind/libunwind/tests)

# helper lib to contain file needed by some tests
add_library(libunwindtest-support
        ${LIBUNWIND_TEST_DIR}/ident.c
        ${LIBUNWIND_TEST_DIR}/flush-cache.S
        ${LIBUNWIND_TEST_DIR}/test-static-link-gen.c
        ${LIBUNWIND_TEST_DIR}/flush-cache.h
        test_support.c
    )
target_compile_options(libunwindtest-support PRIVATE -Wno-error -DUNW_LOCAL_ONLY=1)
target_include_directories(libunwindtest-support PUBLIC
        ${PROJECT_SOURCE_DIR}/3rdparty/libunwind
        ${PROJECT_BINARY_DIR}/3rdparty/libunwind
        ${PROJECT_SOURCE_DIR}/3rdparty/libunwind/libunwind/include
    )
target_link_libraries(libunwindtest-support PUBLIC oelibcxx oeenclave)

function(add_libunwind_test_enc NAME TESTFILE)
    add_executable(libunwindtest-${NAME}_enc
        enc.c
        ${PROJECT_SOURCE_DIR}/${TESTFILE}
        )
    target_include_directories(libunwindtest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_BINARY_DIR}/3rdparty/libunwind/libunwind/tests
        )
    target_compile_options(libunwindtest-${NAME}_enc
        PRIVATE
        -Wno-error
        -Wno-macro-redefined # We need `UNW_LOCAL_ONLY=1` but some files already define it.
        -fno-inline-functions)
    if(("${NAME}" STREQUAL "Ltest-varargs") AND ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
        target_compile_options(libunwindtest-${NAME}_enc PRIVATE -include enc/clang_varargs_extra.h)
    endif()
    target_compile_definitions(libunwindtest-${NAME}_enc PRIVATE
        -DWITH_MAIN -D__TEST__="${TESTFILE}" -DUNW_LOCAL_ONLY=1)
    target_link_libraries(libunwindtest-${NAME}_enc libunwindtest-support)
    target_link_libraries(libunwindtest-${NAME}_enc -Wl,--undefined=pthread_mutex_lock)
    target_link_libraries(libunwindtest-${NAME}_enc -Wl,--undefined=_U_dyn_info_list_addr)
endfunction(add_libunwind_test_enc)

file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "3rdparty/libunwind/libunwind/tests/")
    add_libunwind_test_enc("${name}" "${testcase}")
endforeach(testcase)
