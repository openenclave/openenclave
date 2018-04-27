# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)
include_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls/mbedtls-wrap-prefix/src/mbedtls-wrap/include/)
# helper lib to contain file needed by some tests
add_library (libmbedtest-support_enc
    enc.cpp
   )
target_compile_options(libmbedtest-support_enc PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )
target_link_libraries(libmbedtest-support_enc PUBLIC oelibcxx)
target_link_libraries(libmbedtest-support_enc INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libmbed_test_enc NAME CXXFILE)
    #message("libcxx-test NAME=${NAME} CXXFILE=${CXXFILE}")
    add_enclave_executable(libmbedtest-${NAME}_enc sign.conf private.pem
        main.cpp
        )

    target_include_directories(libmbedtest-${NAME}_enc PUBLIC
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
        )
    target_compile_options(libmbedtest-${NAME}_enc PRIVATE --std=c++14)
    target_compile_definitions(libmbedtest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libmbedtest-${NAME}_enc mbedcrypto )
    target_link_libraries(libmbedtest-${NAME}_enc libmbedtest-support_enc)
endfunction(add_libmbed_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/mbedtls/mbedtls/programs/test/")
    add_libmbed_test_enc("${name}" "${testcase}")
endforeach(testcase)
