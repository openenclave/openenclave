# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

include(./tests.cmake)

if (OE_SEPARATE_LIBC_TESTS)
    foreach(testcase ${LIBC_TESTS})
        get_testcase_name(${testcase} name "${PROJECT_SOURCE_DIR}")
        add_enclave_test(tests/libc-${name} libc_host libc-${name}_enc)
    endforeach(testcase)
else ()
    add_enclave_test(tests/libc-all libc_host libc_enc)
endif ()
