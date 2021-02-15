# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl_unsupported.edl)

add_custom_command(
  OUTPUT openssl_unsupported_t.h openssl_unsupported_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

function (add_unsupported_test NAME)
  set(DEFINE OE_${NAME})
  string(TOUPPER ${DEFINE} DEFINE)
  string(TOLOWER ${NAME} NAME)

  add_enclave(TARGET openssl_unsupported_${NAME}_enc SOURCES enc.c
              ${CMAKE_CURRENT_BINARY_DIR}/openssl_unsupported_t.c)

  # Suppress Werror to verify that the compilation still fails as expected.
  enclave_compile_options(openssl_unsupported_${NAME}_enc PRIVATE -Wno-error)

  enclave_compile_definitions(openssl_unsupported_${NAME}_enc PRIVATE ${DEFINE})

  enclave_include_directories(openssl_unsupported_${NAME}_enc PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})

  enclave_link_libraries(openssl_unsupported_${NAME}_enc openssl oelibc
                         oehostsock oehostfs oehostresolver)

  if (WIN32)
    maybe_build_using_clangw(openssl_unsupported_${NAME}_enc)

    # maybe_build_using_clangw populates variables in its parent scope (ie current scope)
    # Propagate these variables back up to the caller.

    # Propagate library names variables.
    set(CMAKE_STATIC_LIBRARY_PREFIX
        "${CMAKE_STATIC_LIBRARY_PREFIX}"
        PARENT_SCOPE)
    set(CMAKE_STATIC_LIBRARY_SUFFIX
        "${CMAKE_STATIC_LIBRARY_SUFFIX}"
        PARENT_SCOPE)

    # Propagate library tool variables.
    set(CMAKE_C_CREATE_STATIC_LIBRARY
        "${CMAKE_C_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)
    set(CMAKE_CXX_CREATE_STATIC_LIBRARY
        "${CMAKE_CXX_CREATE_STATIC_LIBRARY}"
        PARENT_SCOPE)

    # Propagate linker variables.
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

    # Propagate cpmpiler variables.
    set(CMAKE_C_COMPILE_OBJECT
        "${CMAKE_C_COMPILE_OBJECT}"
        PARENT_SCOPE)
    set(CMAKE_CXX_COMPILE_OBJECT
        "${CMAKE_CXX_COMPILE_OBJECT}"
        PARENT_SCOPE)
  endif ()

  # Exclude the enclave from build.
  # From: https://stackoverflow.com/questions/30155619/expected-build-failure-tests-in-cmake
  set_enclave_properties(openssl_unsupported_${NAME}_enc PROPERTIES
                         EXCLUDE_FROM_ALL TRUE EXCLUDE_FROM_DEFAULT_BUILD TRUE)

  add_test(
    NAME openssl_unsupported_${NAME}
    COMMAND ${CMAKE_COMMAND} --build . --target openssl_unsupported_${NAME}_enc
            --config $<CONFIGURATION>
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

  # The compilation of the baseline case (i.e., not linking against any of unsupported APIs
  # but simply including the headers) is expected to succeed.
  if (NOT ${NAME} STREQUAL "baseline")
    # In addition to expecting the compilation to fail, checking whether the log includes
    # the specific error message, which indicates the unsupported.h header is
    # correctly included.
    set_tests_properties(
      openssl_unsupported_${NAME}
      PROPERTIES
        WILL_FAIL
        TRUE
        FAIL_REGULAR_EXPRESSION
        "warning: .* is deprecated: The function|macro may be unsafe inside an enclave"
    )
  endif ()

endfunction (add_unsupported_test)

set(UNSUPPORTED_LIST
    BASELINE
    OPENSSL_INIT_LOAD_CONFIG
    SSL_CTX_set_default_verify_paths
    SSL_CTX_set_default_verify_dir
    SSL_CTX_set_default_verify_file
    SSL_CTX_load_verify_locations
    X509_load_cert_file
    X509_load_crl_file
    X509_load_cert_crl_file
    X509_LOOKUP_hash_dir
    X509_LOOKUP_file
    X509_STORE_load_locations
    X509_STORE_set_default_paths)

foreach (name ${UNSUPPORTED_LIST})
  add_unsupported_test(${name})
endforeach (name)
