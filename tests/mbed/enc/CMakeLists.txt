# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)
include_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls/mbedtls-wrap-prefix/src/mbedtls-wrap/include/)
# helper lib to contain file needed by some tests

# helper function to create enclave binary
function(add_libmbed_test_enc NAME )
    #message("libcxx-test NAME=${NAME} CXXFILE=${CXXFILE}")
   
   string(FIND "${NAME}" "." cond)
   if(${cond} GREATER 0 )  
           set(data_name ${NAME})
           string(REPLACE "." ";" suite ${NAME})
           list(GET suite 0 suite_name)    
   elseif(${cond} LESS 0 )
           set(suite_name ${NAME})
           set(data_name ${NAME})
   endif()

    add_custom_command(
        OUTPUT test_suite_${data_name}
        COMMAND ${PERL_EXECUTABLE} ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/scripts/generate_code.pl ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/suites test_suite_${suite_name} test_suite_${data_name}
        DEPENDS ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/scripts/generate_code.pl mbedcrypto ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/suites/helpers.function ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/suites/main_test.function ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/suites/test_suite_${suite_name}.function ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/suites/test_suite_${data_name}.data
   #COMMAND ${CMAKE_COMMAND} -E copy
   #       test_suite_${data_name}.c  ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/suites/
   )

    add_enclave_executable(libmbedtest_suite_${NAME} sign.conf private.pem test_suite_${NAME} 
     enc.c
     main.c
    )
    target_compile_options(libmbedtest_suite_${NAME} PRIVATE
      -Wno-error
    )

    target_include_directories(libmbedtest_suite_${NAME} PUBLIC
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
        )
    target_compile_definitions(libmbedtest_suite_${NAME} PRIVATE -DWITH_MAIN -D__TEST__="${CMAKE_CURRENT_BINARY_DIR}/test_suite_${NAME}.c")
    target_link_libraries(libmbedtest_suite_${NAME} mbedcrypto oelibc )
endfunction(add_libmbed_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests_suites.supported" alltests)
foreach(testcase ${alltests})
#    get_testcase_name(${testcase} name "../../3rdparty/mbedtls/mbedtls/programs/test/")
    add_libmbed_test_enc(${testcase})
endforeach(testcase)
File(COPY ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/data_files DESTINATION ${CMAKE_BINARY_DIR}/tests/mbed )
