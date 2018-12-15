# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Create a binary for each testcase listed in ../tests.supported
# These tests generate a large number of warnings, some of them specific to compiler versions.
# Disabling warning-as-errors for the specific warnings is painful across multiple different compilers.
# It was agreed to, that it is best to just disable warnings-as-errors for these tests specifically.

include(oeedl_file)
include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

oeedl_file(../libc.edl enclave gen)

# helper lib to contain file needed by some tests
add_library(libctest-support
    mtest.c
    rand.c
    tls_align_dso.c
    )
target_compile_options(libctest-support PRIVATE
    -Wno-error
    )
target_link_libraries(libctest-support PUBLIC oelibc oeenclave oecore)

function(add_libc_test_enc NAME CFILE)
    add_executable(libctest-${NAME}_enc enc.c main.c ${gen})

    target_include_directories(libctest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        )
    target_compile_options(libctest-${NAME}_enc PRIVATE
        -Wno-error
        -Wno-unknown-pragmas
        -Wno-unused-function
        )
    target_compile_definitions(libctest-${NAME}_enc PRIVATE -D__TEST__="${CFILE}")
    target_link_libraries(libctest-${NAME}_enc libctest-support)
endfunction(add_libc_test_enc)

file(STRINGS "../tests.supported" alltests)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
foreach(testcase ${alltests})
    if (CMAKE_C_COMPILER_ID MATCHES Clang)
        if (BUILD_TYPE_UPPER MATCHES DEBUG)
	    if (${testcase} IN_LIST clang_debug_skipped_libc_tests)
		continue ()
	    endif ()
        elseif (BUILD_TYPE_UPPER MATCHES REL)
	    if (${testcase} IN_LIST clang_release_skipped_libc_tests)
		continue ()
	    endif ()
        endif()
    endif()

    get_testcase_name(${testcase} name "../../3rdparty/musl/libc-test/src/")
    add_libc_test_enc("${name}" "${testcase}")
endforeach(testcase)
