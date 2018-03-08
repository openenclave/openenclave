# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../libc/get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libcxxtest-support
    enc.cpp
    fuzzing.cpp
    memory_resource.cpp
    )
target_compile_options(libcxxtest-support PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    -Wno-error=attributes
    -Wno-error=maybe-uninitialized
    -Wno-error=strict-overflow
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-local-typedefs
    -Wno-error=unused-variable
    )
target_link_libraries(libcxxtest-support PUBLIC oelibcxx)
target_link_libraries(libcxxtest-support INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libcxx_test_enc NAME CXXFILE)
    #message("libcxx-test NAME=${NAME} CXXFILE=${CXXFILE}")
    add_enclave_executable(libcxxtest-${NAME} sign.conf private.pem
        main.cpp
        )

    target_include_directories(libcxxtest-${NAME} PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
        )

    target_compile_options(libcxxtest-${NAME} PRIVATE -Wno-error --std=c++14)
    target_compile_definitions(libcxxtest-${NAME} PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libcxxtest-${NAME} libcxxtest-support)
endfunction(add_libcxx_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name)
    add_libcxx_test_enc("${name}" "${testcase}")
endforeach(testcase)
