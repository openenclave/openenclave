# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


# >> In one of the test "ssl" we are using a variable called new which is a function in C++
#    causes improper behaviour at compile time leads us to use C instead of C++


include(${CMAKE_CURRENT_LIST_DIR}/../../../cmake/get_testcase_name.cmake)
include_directories(${CMAKE_BINARY_DIR}/3rdparty/mbedtls/mbedtls-wrap-prefix/src/mbedtls-wrap/include/)
# helper lib to contain file needed by some tests

oeedl_file(../mbed.edl enclave gen)

# helper function to create enclave binary
function(add_libmbed_test_enc NAME )
   
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
   )

    add_executable(libmbedtest_suite_${NAME} test_suite_${NAME} 
     enc.c
     main.c
     start.S
     ${gen}
    )
    target_compile_options(libmbedtest_suite_${NAME} PRIVATE
      -Wno-error
    )


    target_include_directories(libmbedtest_suite_${NAME} PUBLIC
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
        )
    target_compile_definitions(libmbedtest_suite_${NAME} PRIVATE -DWITH_MAIN -D__TEST__="${CMAKE_CURRENT_BINARY_DIR}/test_suite_${NAME}.c")
    target_link_libraries(libmbedtest_suite_${NAME} mbedcrypto oelibc oecore)
endfunction(add_libmbed_test_enc)

function(add_libmbed_selftest_enc NAME SOURCE )
    add_executable(libmbedtest-${NAME}_enc enc.c main.c start.S ${gen})

    target_include_directories(libmbedtest-${NAME}_enc PUBLIC
        ..
        ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
        )

    target_compile_options(libmbedtest-${NAME}_enc PRIVATE -Wno-conversion -Wno-pointer-arith)
    target_compile_definitions(libmbedtest-${NAME}_enc PRIVATE -DWITH_MAIN -D__TEST__="${SOURCE}")
    target_link_libraries(libmbedtest-${NAME}_enc mbedcrypto oelibc oecore)

endfunction(add_libmbed_selftest_enc)

string(TOUPPER ${CMAKE_BUILD_TYPE} build_type)
if (NOT "${build_type}" STREQUAL "DEBUG")
	set(is_nondebug_build TRUE)
endif()

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
	string(FIND "${testcase}" "selftest" found_selftest)
	if(${found_selftest} GREATER 0 )
		get_testcase_name(${testcase} name "../../3rdparty/mbedtls/mbedtls/programs/test/")
		add_libmbed_selftest_enc( ${name} ${testcase})
     else()
		if(${is_nondebug_build})
			string(FIND "${testcase}" "debug" found_debug)
			if(NOT ${found_debug} LESS 0)
				continue()
			endif()
		endif()
	add_libmbed_test_enc(${testcase})
	endif()
endforeach(testcase)

File(COPY ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/data_files DESTINATION ${CMAKE_BINARY_DIR}/tests/mbed )
