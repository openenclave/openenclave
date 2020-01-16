# Copyright (c) Open Enclave SDK contributors.
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
elseif (LINUX_BIN_DIR)
    # Find the build information from pre-compiled tests. If found, `LINUX_CXX_COMPILER_ID`
    # and `LINUX_CXX_COMPILER_VERSION` will hold the corresponding information.
    list(APPEND CMAKE_MODULE_PATH "${LINUX_BIN_DIR}/libcxx/enc")
    include(build_info OPTIONAL)
endif()

if (ADD_WINDOWS_ENCLAVE_TESTS)
    if (NOT LINUX_CXX_COMPILER_ID OR NOT LINUX_CXX_COMPILER_VERSION)
        message(FATAL_ERROR "Could not find the compiler information of linux tests!")
    endif()
    # Load target LINUX_CXX_COMPILER_ID and LINUX_CXX_COMPILER_VERSION values.
    set(ENCLAVE_CXX_COMPILER_ID ${LINUX_CXX_COMPILER_ID})
    set(ENCLAVE_CXX_COMPILER_VERSION ${LINUX_CXX_COMPILER_VERSION})
else ()
    set(ENCLAVE_CXX_COMPILER_ID ${CMAKE_CXX_COMPILER_ID})
    set(ENCLAVE_CXX_COMPILER_VERSION ${CMAKE_CXX_COMPILER_VERSION})
endif()

foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

# the allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds -- Skip running these tests
    if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass" OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (ENCLAVE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
        endif()
    endif()

# few functions invoked in these tests are not supported in gnu -- Skip running these tests
    if ("${name}" MATCHES "convert_file_time.sh" 
            OR "${name}" MATCHES "sequences_array_at.pass" 
            OR "${name}" MATCHES "libcxx_containers_unord_next_pow2.pass" 
            OR "${name}" MATCHES "std_utilities_template.bitset_bitset.members_count.pass")
        if (ENCLAVE_CXX_COMPILER_ID MATCHES GNU)
            continue()
        endif()
    endif()

# the following test fails when built with clang, see #830 -- Skipping this test in clang
    if ("${name}" MATCHES "array_sized_delete_array_calls_unsized_delete_array.pass")
        if (ENCLAVE_CXX_COMPILER_ID MATCHES Clang)
            continue()
        endif()
    endif()

# the following test fails on GCC version 7, see  #1523 -- Skipping this test in GCC 7.0 -> 7.5
    if ("${name}" MATCHES "std_utilities_function.objects_comparisons_constexpr_init.pass")
        if(ENCLAVE_CXX_COMPILER_ID MATCHES GNU
            AND ENCLAVE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 7
            AND ENCLAVE_CXX_COMPILER_VERSION VERSION_LESS 7.5)
            continue()
        endif()
    endif()

# the following test fails on GCC 7 or newer, see #1559 -- Skip this test on GCC 7.0 and above in non debug builds
    if ("${name}" MATCHES "std_containers_associative_map_map.access_at.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (ENCLAVE_CXX_COMPILER_ID MATCHES GNU AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
        endif()
    endif()

    add_enclave_test(tests/libcxxtest-${name} libcxx_host libcxxtest-${name}_enc)
endforeach(testcase)
