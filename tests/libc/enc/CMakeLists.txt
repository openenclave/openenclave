# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libctest-support
    mtest.c
    rand.c
    tls_align_dso.c
    )
target_compile_options(libctest-support PRIVATE
    -Wno-error=attributes
    -Wno-error=overflow
    -Wno-error=maybe-uninitialized
    -Wno-error=missing-braces
    -Wno-error=strict-overflow
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-function
    -Wno-error=unused-local-typedefs
    -Wno-error=unused-value
    -Wno-error=unused-variable
    )
target_link_libraries(libctest-support PUBLIC oelibc)

function(add_libc_test_enc NAME CFILE)
    add_enclave_executable(libctest-${NAME}_enc sign.conf private.pem
        enc.c
        main.c
        )

    target_include_directories(libctest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/musl/libc-test/src/common
        )
    target_compile_options(libctest-${NAME}_enc PRIVATE
        -Wno-error=missing-braces
        -Wno-error=overflow
        -Wno-error=unused-value
        -Wno-error=unused-variable
        )
    target_compile_definitions(libctest-${NAME}_enc PRIVATE -D__TEST__="${CFILE}")
    target_link_libraries(libctest-${NAME}_enc libctest-support)
endfunction(add_libc_test_enc)

file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name)
    add_libc_test_enc("${name}" "${testcase}")
endforeach(testcase)
