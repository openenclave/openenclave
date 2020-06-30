# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../libcxxrt.edl)

add_custom_command(
  OUTPUT libcxxrt_t.h libcxxrt_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# helper lib to contain file needed by some tests
add_enclave_library(libcxxrttest-support libcxxrt_t.c)
enclave_compile_options(libcxxrttest-support PUBLIC -Wno-error)
enclave_link_libraries(libcxxrttest-support PRIVATE oeenclave oelibc)
enclave_link_libraries(libcxxrttest-support INTERFACE -Wl,--undefined=test)

# helper function to create enclave binary
function (add_libcxxrt_test_enc NAME CXXFILE)
  add_enclave(
    TARGET
    libcxxrttest-${NAME}_enc
    UUID
    c8f14445-7de0-48de-9886-cf8c7a396e94
    CXX
    SOURCES
    enc.cpp
    main.cpp)
  enclave_include_directories(
    libcxxrttest-${NAME}_enc
    PRIVATE
    ..
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/src
    ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/test
    ${CMAKE_CURRENT_BINARY_DIR})
  enclave_compile_definitions(libcxxrttest-${NAME}_enc PRIVATE -DWITH_MAIN
                              -D__TEST__="${CXXFILE}")
  enclave_link_libraries(libcxxrttest-${NAME}_enc libcxxrttest-support)
  if ("${NAME}" STREQUAL "test_foreign_exceptions")
    enclave_link_libraries(libcxxrttest-${NAME}_enc
                           -Wl,--wrap,_Unwind_RaiseException)
  endif ()

  if (WIN32)
    maybe_build_using_clangw(libcxxrttest-${NAME}_enc)

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
endfunction (add_libcxxrt_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach (testcase ${alltests})
  get_testcase_name(${testcase} name "")
  add_libcxxrt_test_enc("${name}" "${testcase}")
endforeach (testcase)
