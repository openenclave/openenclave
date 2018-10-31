# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported
include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libcxxrttest-support
    enc.cpp
    )
target_compile_options(libcxxrttest-support PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    -Wno-error
    -Wconversion
    -Wpointer-arith
    )
target_link_libraries(libcxxrttest-support PUBLIC oelibcxx oeenclave)
target_link_libraries(libcxxrttest-support INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libcxxrt_test_enc NAME CXXFILE)
    add_executable(libcxxrttest-${NAME}_enc main.cpp)
    target_include_directories(libcxxrttest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/src
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/test
        )
    target_compile_options(libcxxrttest-${NAME}_enc PRIVATE -Wno-error --std=c++14)
    target_compile_definitions(libcxxrttest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libcxxrttest-${NAME}_enc libcxxrttest-support oelibcxx oelibc cxxrt-static)
    if("${NAME}" STREQUAL "test_foreign_exceptions")
        target_link_libraries(libcxxrttest-${NAME}_enc -Wl,--wrap,_Unwind_RaiseException)
    endif()
endfunction(add_libcxxrt_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "")
    add_libcxxrt_test_enc("${name}" "${testcase}")
endforeach(testcase)
