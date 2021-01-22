# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Read tests.supported, sanitize the cpp-file, and create the test-case.
if (ENABLE_FULL_LIBCXX_TESTS)
  file(STRINGS "tests.supported" alltests)
else ()
  file(STRINGS "tests.supported.default" alltests)
endif ()

# The list of tests requires `std=c++17`.
file(STRINGS "tests.supported.cxx17" CXX_17_TEST_LIST)

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
elseif (LINUX_BIN_DIR)
  # Find the build information from pre-compiled tests. If found, `LINUX_CXX_COMPILER_ID`
  # and `LINUX_CXX_COMPILER_VERSION` will hold the corresponding information.
  list(APPEND CMAKE_MODULE_PATH "${LINUX_BIN_DIR}/libcxx/enc")
  include(build_info OPTIONAL)
endif ()

if (ADD_WINDOWS_ENCLAVE_TESTS)
  if (NOT LINUX_CXX_COMPILER_ID OR NOT LINUX_CXX_COMPILER_VERSION)
    message(
      FATAL_ERROR "Could not find the compiler information of linux tests!")
  endif ()
  # Load target LINUX_CXX_COMPILER_ID and LINUX_CXX_COMPILER_VERSION values.
  set(ENCLAVE_CXX_COMPILER_ID ${LINUX_CXX_COMPILER_ID})
  set(ENCLAVE_CXX_COMPILER_VERSION ${LINUX_CXX_COMPILER_VERSION})
else ()
  set(ENCLAVE_CXX_COMPILER_ID ${CMAKE_CXX_COMPILER_ID})
  set(ENCLAVE_CXX_COMPILER_VERSION ${CMAKE_CXX_COMPILER_VERSION})
endif ()

foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

  # The allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds -- Skip running these tests
  if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass"
      OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
    if (ENCLAVE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
      continue()
    endif ()
  endif ()

  # The following test fails when built with clang, see #830 -- Skipping this test in clang
  if ("${name}" MATCHES
      "array_sized_delete_array_calls_unsized_delete_array.pass")
    if (ENCLAVE_CXX_COMPILER_ID MATCHES Clang)
      continue()
    endif ()
  endif ()

  add_enclave_test(tests/libcxxtest-${name} libcxx_host libcxxtest-${name}_enc)
endforeach (testcase)
