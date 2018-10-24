# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libcxxthrdtest-support
    enc.cpp
    fuzzing.cpp
    memory_resource.cpp
    )

target_compile_options(libcxxthrdtest-support PRIVATE
    -std=c++14
    -Wno-error=attributes
    -Wno-error=strict-overflow
    -Wno-error=unused-local-typedefs
    -Wno-error=unused-variable
    )

if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
    target_compile_options(libcxxthrdtest-support PRIVATE
      -Wno-error=maybe-uninitialized
      -Wno-error=unused-but-set-variable
      )
endif ()

target_link_libraries(libcxxthrdtest-support PUBLIC oelibcxx oeenclave)
target_link_libraries(libcxxthrdtest-support INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libcxxthrd_test_enc NAME CXXFILE)
    add_executable(libcxxthrdtest-${NAME}_enc main.cpp)

    target_include_directories(libcxxthrdtest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
        )

    target_compile_options(libcxxthrdtest-${NAME}_enc PRIVATE
        -std=c++14
        # These are third-party tests, so we don't care about their warnings.
        -Wno-error
        # Remove NDEBUG to enable the libcxxthrd testsuite assertions in Release
        -UNDEBUG
        )

    # Clang does not support variants of operator delete[] taking size_t in C++14 unless
    # -fsized-deallocation is passed explicity. (Note, gcc 4.7/4.8/4.9 do not support this either.)
    # NOTE: This only matters when `ENABLE_FULL_LIBCXX_TESTS=ON`.
    if (NAME MATCHES "sized_delete_array14")
        target_compile_options(libcxxthrdtest-${NAME}_enc PRIVATE -fsized-deallocation)
    endif()

    target_compile_definitions(libcxxthrdtest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libcxxthrdtest-${NAME}_enc libcxxthrdtest-support oeenclave)
endfunction(add_libcxxthrd_test_enc)

# iterate over the supported tests and create a binary for each.
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "../tests.supported" alltests)
else()
    file(STRINGS "../tests.supported.default" alltests)
endif()
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")
    add_libcxxthrd_test_enc("${name}" "${testcase}")
endforeach(testcase)
