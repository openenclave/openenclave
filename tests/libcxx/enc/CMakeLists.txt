# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

oeedl_file(../libcxx.edl enclave gen)

include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libcxxtest-support
    enc.cpp
    fuzzing.cpp
    memory_resource.cpp
    ${gen}
    )

target_compile_options(libcxxtest-support PRIVATE
    -Wno-error=attributes
    -Wno-error=strict-overflow
    -Wno-error=unused-local-typedefs
    -Wno-error=unused-variable
    -Wno-sign-conversion
    )

if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
    target_compile_options(libcxxtest-support PRIVATE
        -Wno-error=maybe-uninitialized
        -Wno-error=unused-but-set-variable
        )
endif ()

target_link_libraries(libcxxtest-support PRIVATE oelibcxx oeenclave)
target_link_libraries(libcxxtest-support INTERFACE -Wl,--undefined=Test)

target_include_directories(libcxxtest-support PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        )

# helper function to create enclave binary
function(add_libcxx_test_enc NAME CXXFILE)
    add_enclave(TARGET libcxxtest-${NAME}_enc CXX SOURCES
        main.cpp ${gen})

    target_include_directories(libcxxtest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/src/filesystem
        )

      target_compile_options(libcxxtest-${NAME}_enc PRIVATE

        # These are third-party tests, so we don't care about their warnings.
        -Wno-error
        -Wno-unused-function
        -Wno-unused-local-typedef
        -Wno-deprecated-declarations
        # Remove NDEBUG to enable the libcxx testsuite assertions in Release
        -UNDEBUG
        )

    # Clang does not support variants of operator delete[] taking size_t in C++14 unless
    # -fsized-deallocation is passed explicity. (Note, gcc 4.7/4.8/4.9 do not support this either.)
    # NOTE: This only matters when `ENABLE_FULL_LIBCXX_TESTS=ON`.
    if (NAME MATCHES "sized_delete")
        target_compile_options(libcxxtest-${NAME}_enc PRIVATE -fsized-deallocation)
    endif()

    target_compile_definitions(libcxxtest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libcxxtest-${NAME}_enc libcxxtest-support)
endfunction(add_libcxx_test_enc)

# iterate over the supported tests and create a binary for each.
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "../tests.supported" alltests)
else()
    file(STRINGS "../tests.supported.default" alltests)
endif()
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

# the allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds
    if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass" OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
        string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
        if (CMAKE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
            continue()
	endif()
    endif()

# few functions invoked in these tests are not supported in gnu and excluded from GCC builds
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

    add_libcxx_test_enc("${name}" "${testcase}")
endforeach(testcase)
