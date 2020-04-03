# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Read tests.supported, sanitize the cpp-file, and create the test-case.
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "tests.supported" alltests)
else()
    file(STRINGS "tests.supported.default" alltests)
endif()

# The list of tests requires `std=c++17`.
file(STRINGS "tests.supported.cxx17" CXX_17_TEST_LIST)

# List of unsupported tests with GCC.
set(GCC_UNSUPPORTED_LIST
    "libcxx_containers_unord_next_pow2.pass"
    "libcxx_input.output_filesystems_convert_file_time.sh"
    "libcxx_numerics_c.math_constexpr-fns.pass"
    "std_containers_sequences_array_at.pass"
    "std_depr_depr.c.headers_string_h.pass"
    "std_depr_depr.c.headers_wchar_h.pass"
    "std_strings_c.strings_cstring.pass"
    "std_strings_c.strings_cwchar.pass"
    "std_utilities_meta_meta.unary_meta.unary.prop_is_trivially_copyable.pass"
    "std_utilities_optional_optional.object_optional.object.assign_emplace_initializer_list.pass"
    "std_utilities_optional_optional.object_optional.object.ctor_copy.pass"
    "std_utilities_template.bitset_bitset.members_count.pass"
    "std_utilities_variant_variant.variant_variant.ctor_in_place_index_init_list_args.pass"
    # The following tests require the revision of "template argument deduction for class templates" feature
    # supported by gcc 8 (SD-6 feature test: __cpp_deduction_guides >= 201611).
    # Refer to https://gcc.gnu.org/projects/cxx-status.html#cxx17 for C++ standard support in gcc.
    "std_containers_container.adaptors_priority.queue_priqueue.cons_deduct.pass"
    "std_containers_container.adaptors_queue_queue.cons_deduct.pass"
    "std_containers_container.adaptors_stack_stack.cons_deduct.pass"
    "std_containers_sequences_array_array.cons_deduct.pass"
    "std_containers_sequences_deque_deque.cons_deduct.pass"
    "std_containers_sequences_forwardlist_forwardlist.cons_deduct.pass"
    "std_containers_sequences_list_list.cons_deduct.pass"
    "std_containers_sequences_vector_vector.cons_deduct.pass"
    "std_re_re.regex_re.regex.construct_deduct.pass"
    "std_strings_basic.string_string.cons_implicit_deduction_guides.pass"
    "std_strings_basic.string_string.cons_iter_alloc_deduction.pass"
    "std_strings_basic.string_string.cons_string_view_deduction.pass"
    "std_strings_basic.string_string.cons_string_view_size_size_deduction.pass"
    "std_utilities_optional_optional.object_optional.object.ctor_deduct.pass"
    "std_utilities_tuple_tuple.tuple_tuple.cnstr_implicit_deduction_guides.pass"
    "std_utilities_utility_pairs_pairs.pair_implicit_deduction_guides.pass"
)

# List the unsupported on GCC version less than 7.
# Refer to https://gcc.gnu.org/bugzilla/show_bug.cgi?id=77446 for the issue.
set(GCC_LESS_7_UNSUPPORTED_LIST
    "std_strings_string.view_string.view.find_find_char_size.pass"
    "std_strings_string.view_string.view.find_find_first_not_of_pointer_size.pass"
    "std_strings_string.view_string.view.find_find_first_not_of_pointer_size_size.pass"
    "std_strings_string.view_string.view.find_find_first_of_char_size.pass"
    "std_strings_string.view_string.view.find_find_last_not_of_pointer_size.pass"
    "std_strings_string.view_string.view.find_find_last_of_pointer_size.pass"
    "std_strings_string.view_string.view.find_find_last_of_pointer_size_size.pass"
)

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

    # The allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds -- Skip running these tests
    if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass" OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (ENCLAVE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
        endif()
    endif()

    # Few functions invoked in these tests are not supported in gnu -- Skip running these tests
    if ("${name}" IN_LIST GCC_UNSUPPORTED_LIST)
        if (ENCLAVE_CXX_COMPILER_ID MATCHES GNU)
            continue()
        endif()
    endif()

    # The following test fails when built with clang, see #830 -- Skipping this test in clang
    if ("${name}" MATCHES "array_sized_delete_array_calls_unsized_delete_array.pass")
        if (ENCLAVE_CXX_COMPILER_ID MATCHES Clang)
            continue()
        endif()
    endif()

    # The following test fails on GCC version 7, see  #1523 -- Skipping this test in GCC 7.0 -> 8.0
    if ("${name}" MATCHES "std_utilities_function.objects_comparisons_constexpr_init.pass")
        if(ENCLAVE_CXX_COMPILER_ID MATCHES GNU
            AND ENCLAVE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 7
            AND ENCLAVE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
            continue()
        endif()
    endif()

    # The following test fails on GCC 7 or newer, see #1559 -- Skip this test on GCC 7.0 and above in non debug builds
    if ("${name}" MATCHES "std_containers_associative_map_map.access_at.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (ENCLAVE_CXX_COMPILER_ID MATCHES GNU AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
        endif()
    endif()

    # Skip the following tests on GCC version less than 7 because a bug is not fixed or C++17 features are not supported.
    if ("${name}" IN_LIST GCC_LESS_7_UNSUPPORTED_LIST OR "${testcase}" IN_LIST CXX_17_TEST_LIST)
        if (ENCLAVE_CXX_COMPILER_ID MATCHES GNU AND ENCLAVE_CXX_COMPILER_VERSION VERSION_LESS 7.0)
            continue()
        endif()
    endif()

    add_enclave_test(tests/libcxxtest-${name} libcxx_host libcxxtest-${name}_enc)
endforeach(testcase)
