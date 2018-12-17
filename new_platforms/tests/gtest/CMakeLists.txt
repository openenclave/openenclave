# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(gtest STATIC
    ${GTEST_PATH}/googletest/src/gtest-all.cc
    ${GTEST_PATH}/googletest/src/gtest_main.cc)

target_include_directories(gtest PRIVATE ${GTEST_PATH}/googletest)
target_include_directories(gtest PUBLIC ${GTEST_PATH}/googletest/include)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_compile_options(gtest PUBLIC "/EHsc")
endif()
