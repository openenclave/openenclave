include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../get_testcase_name.cmake)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../../3rdparty/mbedtls/mbedtls/include/)

# helper lib to contain file needed by some tests
add_library (libmbedtest-support
    enc.cpp
   )
target_compile_options(libmbedtest-support PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )
target_link_libraries(libmbedtest-support PUBLIC oelibcxx)
target_link_libraries(libmbedtest-support INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libmbed_test_enc NAME CXXFILE)
    #message("libcxx-test NAME=${NAME} CXXFILE=${CXXFILE}")
    add_enclave_executable(libmbedtest-${NAME} sign.conf private.pem
        main.cpp
        )

    target_include_directories(libmbedtest-${NAME} PUBLIC
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
        )
    target_compile_options(libmbedtest-${NAME} PRIVATE -Wno-error --std=c++14)
    target_compile_definitions(libmbedtest-${NAME} PRIVATE -DWITH_MAIN -D__TEST__="${CXXFILE}")
    target_link_libraries(libmbedtest-${NAME} mbedcrypto )
    target_link_libraries(libmbedtest-${NAME} libmbedtest-support)
endfunction(add_libmbed_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name)
    add_libmbed_test_enc("${name}" "${testcase}")
endforeach(testcase)
