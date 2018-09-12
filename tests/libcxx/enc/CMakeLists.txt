# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

include(add_compile_flags_if_supported)
include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libcxxtest-support
    enc.cpp
    fuzzing.cpp
    memory_resource.cpp
    )
target_compile_options(libcxxtest-support PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )

add_target_compile_flags_if_supported(libcxxtest-support PRIVATE CXX
    -Wno-error=attributes
    -Wno-error=maybe-uninitialized
    -Wno-error=strict-overflow
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-local-typedefs
    -Wno-error=unused-variable
    )

target_link_libraries(libcxxtest-support PUBLIC oelibcxx oeenclave)
target_link_libraries(libcxxtest-support INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libcxx_test_enc NAME CXXFILE)
    #message("libcxx-test NAME=${NAME} CXXFILE=${CXXFILE}")
    add_executable(libcxxtest-${NAME}_enc main.cpp)

    target_include_directories(libcxxtest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
        )

    # Remove NDEBUG to enable the libcxx testsuite assertions in Release
    target_compile_options(libcxxtest-${NAME}_enc PRIVATE -Wno-error --std=c++14 -UNDEBUG)

    # Clang does not support variants of operator delete[] taking size_t in C++14 unless
    # -fsized-deallocation is passed explicity. (Note, gcc 4.7/4.8/4.9 do not support this either.)
    if ("${NAME}" MATCHES "sized_delete_array14")
        add_target_compile_flags_if_supported(libcxxtest-${NAME}_enc PRIVATE CXX -fsized-deallocation)
    endif()
    target_compile_definitions(libcxxtest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libcxxtest-${NAME}_enc libcxxtest-support oeenclave)
endfunction(add_libcxx_test_enc)

# iterate over the supported tests and create a binary for each.
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "../tests.supported" alltests)
else()
    file(STRINGS "../tests.supported.default" alltests)
endif()
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")
    add_libcxx_test_enc("${name}" "${testcase}")
endforeach(testcase)
