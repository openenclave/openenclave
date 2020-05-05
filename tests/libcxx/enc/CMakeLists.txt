# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# create a binary for each testcase listed in ../tests.supported

set(EDL_FILE ../libcxx.edl)

add_custom_command(
  OUTPUT libcxx_t.h libcxx_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# helper lib to contain file needed by some tests
add_enclave_library(libcxxtest-support enc.cpp fuzzing.cpp memory_resource.cpp
                    libcxx_t.c)

enclave_compile_options(
  libcxxtest-support
  PRIVATE
  -Wno-error=attributes
  -Wno-error=strict-overflow
  -Wno-error=unused-local-typedefs
  -Wno-error=unused-variable
  -Wno-sign-conversion)

if (ENABLE_FULL_LIBCXX_TESTS)
  enclave_compile_definitions(libcxxtest-support PRIVATE FULL_LIBCXX_TESTS)
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
  enclave_compile_options(
    libcxxtest-support PRIVATE -Wno-error=maybe-uninitialized
    -Wno-error=unused-but-set-variable)
endif ()

enclave_link_libraries(libcxxtest-support PRIVATE oelibcxx oeenclave)
enclave_link_libraries(libcxxtest-support INTERFACE -Wl,--undefined=Test)

enclave_include_directories(libcxxtest-support PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

# Log the build information.
set(BUILD_INFO_FILE "${CMAKE_CURRENT_BINARY_DIR}/build_info.cmake")
file(WRITE "${BUILD_INFO_FILE}"
     "set(LINUX_CXX_COMPILER_ID \"${CMAKE_CXX_COMPILER_ID}\")\n")
file(APPEND "${BUILD_INFO_FILE}"
     "set(LINUX_CXX_COMPILER_VERSION \"${CMAKE_CXX_COMPILER_VERSION}\")\n")

# helper function to create enclave binary
function (add_libcxx_test_enc NAME CXXFILE)
  add_enclave(
    TARGET
    libcxxtest-${NAME}_enc
    UUID
    486dcdcc-f0c6-4bdd-91e0-c7566794f899
    CXX
    # Building the enclave by default when enabling LVI mitigation to
    # test linking against LVI-mitigated libraries.
    ADD_LVI_MITIGATION
    SOURCES
    main.cpp
    libcxx_t.c)

  enclave_include_directories(
    libcxxtest-${NAME}_enc
    PRIVATE
    ..
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxx/libcxx/src/filesystem)

  enclave_compile_options(
    libcxxtest-${NAME}_enc
    PRIVATE
    # These are third-party tests, so we don't care about their warnings.
    -Wno-error
    -Wno-unused-function
    -Wno-unused-local-typedef
    -Wno-deprecated-declarations
    # Remove NDEBUG to enable the libcxx testsuite assertions in Release
    -UNDEBUG)

  # Clang does not support variants of operator delete[] taking size_t in C++14 unless
  # -fsized-deallocation is passed explicity. (Note, gcc 4.7/4.8/4.9 do not support this either.)
  # NOTE: This only matters when `ENABLE_FULL_LIBCXX_TESTS=ON`.
  if (NAME MATCHES "sized_delete")
    enclave_compile_options(libcxxtest-${NAME}_enc PRIVATE -fsized-deallocation)
  endif ()

  enclave_compile_definitions(libcxxtest-${NAME}_enc PRIVATE -DWITH_MAIN
                              -D__TEST__="${CXXFILE}")
  enclave_link_libraries(libcxxtest-${NAME}_enc libcxxtest-support)

  if (CXXFILE IN_LIST CXX_17_TEST_LIST)
    set_enclave_property(TARGET libcxxtest-${NAME}_enc PROPERTY CXX_STANDARD 17)
  endif ()

  if (WIN32)
    maybe_build_using_clangw(libcxxtest-${NAME}_enc)

    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables
    set(CMAKE_STATIC_LIBRARY_PREFIX
        "${CMAKE_STATIC_LIBRARY_PREFIX}"
        PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX
        "${CMAKE_STATIC_LIBRARY_SUFFIX}"
        PARENT_SCOPE)

    # Propagate library tool variables
    set(CMAKE_C_CREATE_STATIC_LIBRARY
        "${CMAKE_C_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY
        "${CMAKE_CXX_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)

    # Propagate linker variables
    set(CMAKE_EXECUTABLE_SUFFIX
        "${CMAKE_EXECUTABLE_SUFFIX}"
        PARENT_SCOPE)
    set(CMAKE_C_STANDARD_LIBRARIES
        "${CMAKE_C_STANDARD_LIBRARIES}"
        PARENT_SCOPE)
    set(CMAKE_C_LINK_EXECUTABLE
        "${CMAKE_C_LINK_EXECUTABLE}"
        PARENT_SCOPE)
    set(CMAKE_CXX_STANDARD_LIBRARIES
        "${CMAKE_CXX_STANDARD_LIBRARIES}"
        PARENT_SCOPE)
    set(CMAKE_CXX_LINK_EXECUTABLE
        "${CMAKE_CXX_LINK_EXECUTABLE}"
        PARENT_SCOPE)

    # Propagate cpmpiler variables
    set(CMAKE_C_COMPILE_OBJECT
        "${CMAKE_C_COMPILE_OBJECT}"
        PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT
        "${CMAKE_CXX_COMPILE_OBJECT}"
        PARENT_SCOPE)
  endif ()
endfunction (add_libcxx_test_enc)

# Iterate over the supported tests and create a binary for each.
if (ENABLE_FULL_LIBCXX_TESTS)
  file(STRINGS "../tests.supported" alltests)
else ()
  file(STRINGS "../tests.supported.default" alltests)
endif ()

foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "../../3rdparty/libcxx/libcxx/test/")

  # The allocations are entirely optimized out by Clang in these tests and are excluded from Clang release builds
  if ("${name}" MATCHES "cons_default_throws_bad_alloc.pass"
      OR "${name}" MATCHES "allocator_allocator.members_construct.pass")
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
    if (CMAKE_CXX_COMPILER_ID MATCHES Clang AND BUILD_TYPE_UPPER MATCHES REL)
      continue()
    endif ()
  endif ()

  # Few functions invoked in these tests are not supported in gnu and excluded from GCC builds
  if ("${name}" IN_LIST GCC_UNSUPPORTED_LIST)
    if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
      continue()
    endif ()
  endif ()

  # The following test fails when built with clang, see #830 -- Skipping this test in clang
  if ("${name}" MATCHES
      "array_sized_delete_array_calls_unsized_delete_array.pass")
    if (CMAKE_CXX_COMPILER_ID MATCHES Clang)
      continue()
    endif ()
  endif ()

  # The following test fails on GCC version 7, see  #1523 -- Skipping this test in GCC 7.0 -> 8.0
  if ("${name}" MATCHES
      "std_utilities_function.objects_comparisons_constexpr_init.pass")
    if (CMAKE_CXX_COMPILER_ID MATCHES GNU
        AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 7
        AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
      continue()
    endif ()
  endif ()

  # The following test fails on GCC 7 or newer, see #1559 -- Skip this test on GCC 7.0 and above in non debug builds
  if ("${name}" MATCHES "std_containers_associative_map_map.access_at.pass")
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
    if (CMAKE_CXX_COMPILER_ID MATCHES GNU AND BUILD_TYPE_UPPER MATCHES REL)
      continue()
    endif ()
  endif ()

  # Skip the following tests on GCC version less than 7 because a bug is not fixed or C++17 features are not supported.
  if ("${name}" IN_LIST GCC_LESS_7_UNSUPPORTED_LIST OR "${testcase}" IN_LIST
                                                       CXX_17_TEST_LIST)
    if (CMAKE_CXX_COMPILER_ID MATCHES GNU AND CMAKE_CXX_COMPILER_VERSION
                                              VERSION_LESS 7.0)
      continue()
    endif ()
  endif ()

  add_libcxx_test_enc("${name}" "${testcase}")
endforeach (testcase)
