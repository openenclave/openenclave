# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../libcxxrt.edl enclave gen)

# helper lib to contain file needed by some tests
add_library(libcxxrttest-support ${gen})
target_compile_options(libcxxrttest-support PUBLIC -Wno-error)
target_link_libraries(libcxxrttest-support PRIVATE oeenclave)
target_link_libraries(libcxxrttest-support INTERFACE -Wl,--undefined=test)

# helper function to create enclave binary
function(add_libcxxrt_test_enc NAME CXXFILE)
    add_enclave(TARGET libcxxrttest-${NAME}_enc CXX SOURCES enc.cpp main.cpp)
    target_include_directories(libcxxrttest-${NAME}_enc PRIVATE
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/src
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/test
        ${CMAKE_CURRENT_BINARY_DIR}
        )
    target_compile_definitions(libcxxrttest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libcxxrttest-${NAME}_enc libcxxrttest-support)
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
