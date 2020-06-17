# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()
string(TOUPPER ${CMAKE_BUILD_TYPE} build_type)
if (NOT "${build_type}" STREQUAL "DEBUG")
  set(is_nondebug_build TRUE)
else ()
  set(is_nondebug_build FALSE)
endif ()
foreach (testcase ${alltests})
  string(COMPARE EQUAL "${testcase}" "selftest" found_selftest)
  if (found_selftest)
    add_enclave_test(tests/mbed/selftest libmbedtest_host mbedtest_selftest)
  else ()
    if (${is_nondebug_build})
      string(FIND "${testcase}" "debug" found_debug)
      if (NOT ${found_debug} LESS 0)
        continue()
      endif ()
    endif ()
    add_enclave_test(tests/mbed/${testcase} libmbedtest_host
                     mbedtest_suite_${testcase})
  endif ()
endforeach (testcase)
