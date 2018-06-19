# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Create a binary for each testcase listed in ../tests.supported
# These tests generate a large number of warnings, some of them specific to compiler versions.
# Disabling warning-as-errors for the specific warnings is painful across multiple different compilers.
# It was agreed to, that it is best to just disable warnings-as-errors for these tests specifically.

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

set(LIBUNWIND_LIB_DIR ${PROJECT_BINARY_DIR}/3rdparty/libunwind/libunwind/src/.libs)
function(add_libunwind_test_enc NAME CFILE)
    add_enclave_executable(libunwindtest-${NAME}_enc sign.conf private.pem
        enc.c
        main.c
        )
    add_dependencies(libunwindtest-${NAME}_enc oelibcxx_unwind)
    target_include_directories(libunwindtest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_BINARY_DIR}/3rdparty/libunwind/libunwind/include
        ${PROJECT_BINARY_DIR}/3rdparty/libunwind/libunwind/tests
        )
    target_compile_options(libunwindtest-${NAME}_enc PRIVATE
        -Wno-error
        )
    target_compile_definitions(libunwindtest-${NAME}_enc PRIVATE -D__TEST__="${CFILE}")
    target_link_libraries(libunwindtest-${NAME}_enc ${LIBUNWIND_LIB_DIR}/libunwind-x86_64.a ${LIBUNWIND_LIB_DIR}/libunwind.a)
    target_link_libraries(libunwindtest-${NAME}_enc oelibc oelibcxx)
endfunction(add_libunwind_test_enc)

if (ENABLE_FULL_LIBUNWIND_TESTS)
    file(STRINGS "../tests.supported" alltests)
else()
    file(STRINGS "../tests.supported.default" alltests)
endif()
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libunwind/libunwind/tests/")
    add_libunwind_test_enc("${name}" "${testcase}")
endforeach(testcase)
