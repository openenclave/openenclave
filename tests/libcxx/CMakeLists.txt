# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# read tests.supported, sanitize the cpp-file, and create the test-case
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "tests.supported" alltests)
else()
    file(STRINGS "tests.supported.default" alltests)
endif()

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

# the allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds -- Skip running these tests
    if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass" OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (CMAKE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
        endif()
    endif()

# few functions invoked in these tests are not supported in gnu -- Skip running these tests
    if ("${name}" MATCHES "convert_file_time.sh" 
            OR "${name}" MATCHES "sequences_array_at.pass" 
            OR "${name}" MATCHES "libcxx_containers_unord_next_pow2.pass" 
            OR "${name}" MATCHES "std_utilities_template.bitset_bitset.members_count.pass")
        if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
            continue()
        endif()
    endif()

# the following test fails when built with clang, see #830 -- Skipping this test in clang
    if ("${name}" MATCHES "array_sized_delete_array_calls_unsized_delete_array.pass")
        if (CMAKE_CXX_COMPILER_ID MATCHES Clang)
            continue()
        endif()
    endif()

# the following test fails on GCC version 7, see  #1523 -- Skipping this test in GCC 7.0 -> 7.5
    if ("${name}" MATCHES "std_utilities_function.objects_comparisons_constexpr_init.pass")
        if(CMAKE_CXX_COMPILER_ID MATCHES GNU
               AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 7
               AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 7.5)
            continue()
        endif()
    endif()

    add_enclave_test(tests/libcxxtest-${name} libcxx_host libcxxtest-${name}_enc)
endforeach(testcase)
