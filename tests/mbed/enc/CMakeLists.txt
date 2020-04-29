# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# >> In one of the test "ssl" we are using a variable called new which is a function in C++
#    causes improper behaviour at compile time leads us to use C instead of C++

set (EDL_FILE ../mbed.edl)

add_custom_command(
    OUTPUT mbed_t.h mbed_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# This function creates an enclave for a specific mbedTLS test.
function(add_mbed_test_enclave NAME)
  string(FIND "${NAME}" "." cond)
  if(${cond} GREATER 0 )
    set(data_name ${NAME})
    string(REPLACE "." ";" suite ${NAME})
    list(GET suite 0 suite_name)
  elseif(${cond} LESS 0 )
    set(suite_name ${NAME})
    set(data_name ${NAME})
  endif()

  set(MBEDTLS_TESTS_DIR "${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests")

 string(CONCAT GEN_TEST_CODE_SCRIPT "${MBEDTLS_TESTS_DIR}/scripts/generate_test_code.py"
                                     " --suites-dir ${MBEDTLS_TESTS_DIR}/suites"
                                     " --functions-file ${MBEDTLS_TESTS_DIR}/suites/test_suite_${suite_name}.function"
                                     " --data-file ${MBEDTLS_TESTS_DIR}/suites/test_suite_${data_name}.data"
                                     " --helpers-file ${MBEDTLS_TESTS_DIR}/suites/helpers.function"
                                     " --template-file ${MBEDTLS_TESTS_DIR}/suites/main_test.function"
                                     " --platform-file ${MBEDTLS_TESTS_DIR}/suites/host_test.function"
                                     " --out-dir ${CMAKE_CURRENT_BINARY_DIR}")
  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/test_suite_${NAME}.c
    COMMAND ${OE_BASH} -c "python ${GEN_TEST_CODE_SCRIPT}"
    DEPENDS
    mbedcrypto
    ${MBEDTLS_TESTS_DIR}/scripts/generate_test_code.py
    ${MBEDTLS_TESTS_DIR}/suites/helpers.function
    ${MBEDTLS_TESTS_DIR}/suites/main_test.function
    ${MBEDTLS_TESTS_DIR}/suites/host_test.function
    ${MBEDTLS_TESTS_DIR}/suites/test_suite_${suite_name}.function
    ${MBEDTLS_TESTS_DIR}/suites/test_suite_${data_name}.data)

  add_enclave(TARGET mbedtest_suite_${NAME} UUID 0e405a1d-dd06-49a4-9d46-3f02440cbf0a
    # Building the enclave by default when enabling LVI mitigation to
    # test linking against LVI-mitigated libraries.
    ADD_LVI_MITIGATION
    SOURCES
    ${CMAKE_CURRENT_BINARY_DIR}/test_suite_${NAME}.c
    enc.c
    mbed_t.c)

  enclave_compile_options(mbedtest_suite_${NAME} PRIVATE -Wno-error)
  enclave_compile_definitions(mbedtest_suite_${NAME} PRIVATE -D__TEST__="${NAME}")
  enclave_include_directories(mbedtest_suite_${NAME} PRIVATE
    ..
    ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/mbedtls-wrap-prefix/src/mbedtls-wrap/include/)
  enclave_link_libraries(mbedtest_suite_${NAME} oelibc)

  maybe_build_using_clangw(mbedtest_suite_${NAME})

  # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
  # Propagate these variables back up to the caller.

  # Propagate library names variables
  set(CMAKE_STATIC_LIBRARY_PREFIX "${CMAKE_STATIC_LIBRARY_PREFIX}" PARENT_SCOPE)
  set(CMAKE_STATIC_LIBRARY_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}" PARENT_SCOPE)

  # Propagate library tool variables
  set(CMAKE_C_CREATE_STATIC_LIBRARY "${CMAKE_C_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)
  set(CMAKE_CXX_CREATE_STATIC_LIBRARY "${CMAKE_CXX_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)

  # Propagate linker variables
  set(CMAKE_EXECUTABLE_SUFFIX "${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
  set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES}" PARENT_SCOPE)
  set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE}" PARENT_SCOPE)
  set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES}" PARENT_SCOPE)
  set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE}" PARENT_SCOPE)

  # Propagate cpmpiler variables
  set(CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}" PARENT_SCOPE)
  set(CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}" PARENT_SCOPE)
endfunction()

# This is simpler version of the above for the single "selftest" test
# suite, which does not generate code.
function(add_mbed_selftest_enclave)
  add_enclave(TARGET mbedtest_selftest UUID f4e07b3e-af0a-4558-bd7e-b692bd441b5d
    SOURCES
    selftest_wrapper.c
    enc.c
    mbed_t.c)

  enclave_compile_options(mbedtest_selftest PRIVATE -Wno-conversion -Wno-pointer-arith)
  enclave_compile_definitions(mbedtest_selftest PRIVATE -D__TEST__="selftest")
  enclave_include_directories(mbedtest_selftest PRIVATE
    ..
    ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/3rdparty/mbedtls/mbedtls-wrap-prefix/src/mbedtls-wrap/include/)
  enclave_link_libraries(mbedtest_selftest oelibc)

  # The following variables remain uninitialized on Linux and throw warnings
  # Calling the function maybe_build_using_clangw(mbedtest_selftest) skips setting
  # the following variables on linux and returns noop
  set(CMAKE_C_CREATE_STATIC_LIBRARY "")
  set(CMAKE_CXX_CREATE_STATIC_LIBRARY "")
  set(CMAKE_C_STANDARD_LIBRARIES "")
  set(CMAKE_CXX_STANDARD_LIBRARIES "")

  maybe_build_using_clangw(mbedtest_selftest)

  # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
  # Propagate these variables back up to the caller.

  # Propagate library names variables
  set(CMAKE_STATIC_LIBRARY_PREFIX "${CMAKE_STATIC_LIBRARY_PREFIX}" PARENT_SCOPE)
  set(CMAKE_STATIC_LIBRARY_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}" PARENT_SCOPE)

  # Propagate library tool variables
  set(CMAKE_C_CREATE_STATIC_LIBRARY "${CMAKE_C_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)
  set(CMAKE_CXX_CREATE_STATIC_LIBRARY "${CMAKE_CXX_CREATE_STATIC_LIBRARY}" PARENT_SCOPE)

  # Propagate linker variables
  set(CMAKE_EXECUTABLE_SUFFIX "${CMAKE_EXECUTABLE_SUFFIX}" PARENT_SCOPE)
  set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES}" PARENT_SCOPE)
  set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE}" PARENT_SCOPE)
  set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES}" PARENT_SCOPE)
  set(CMAKE_CXX_LINK_EXECUTABLE "${CMAKE_CXX_LINK_EXECUTABLE}" PARENT_SCOPE)

  # Propagate cpmpiler variables
  set(CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}" PARENT_SCOPE)
  set(CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}" PARENT_SCOPE)
endfunction()

string(TOUPPER ${CMAKE_BUILD_TYPE} build_type)
if (NOT "${build_type}" STREQUAL "DEBUG")
  set(is_nondebug_build TRUE)
else()
  set(is_nondebug_build FALSE)
endif ()

# Here we parse the list of tests and use the functions above to
# create all the enclaves.
file(STRINGS "../tests.supported" alltests)
foreach (testcase ${alltests})
  string(COMPARE EQUAL "${testcase}" "selftest" found_selftest)
  if (found_selftest)
    add_mbed_selftest_enclave()
  else ()
    if (${is_nondebug_build})
      string(FIND "${testcase}" "debug" found_debug)
      if (NOT ${found_debug} LESS 0)
        continue()
      endif ()
    endif ()
    add_mbed_test_enclave(${testcase})
  endif ()
endforeach ()

# These are static data files we just need in our build tree.
file(COPY ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/tests/data_files DESTINATION ${CMAKE_BINARY_DIR}/tests/mbed)
