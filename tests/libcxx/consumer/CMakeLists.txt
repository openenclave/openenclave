# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Standalone installed-SDK check. Do not add this to the SDK's own build:
# its purpose is to test exported headers/targets with a different compiler.
cmake_minimum_required(VERSION 3.20)
project(libcxx_consumer LANGUAGES C CXX)
find_package(OpenEnclave CONFIG REQUIRED)
find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
enable_testing()

if (NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif ()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(sample "${OE_INCLUDEDIR}/../share/openenclave/samples/helloworld")

foreach (side trusted untrusted)
  if (side STREQUAL "trusted")
    set(suffix t)
  else ()
    set(suffix u)
  endif ()
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${side}")
  add_custom_command(
    OUTPUT ${side}/helloworld_${suffix}.c ${side}/helloworld_${suffix}.h
    COMMAND
      openenclave::oeedger8r --${side} ${sample}/helloworld.edl --search-path
      ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${side}
    DEPENDS ${sample}/helloworld.edl)
endforeach ()

add_executable(
  consumer_host ${sample}/host/host.c
                ${CMAKE_CURRENT_BINARY_DIR}/untrusted/helloworld_u.c)
target_include_directories(consumer_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/untrusted)
target_link_libraries(consumer_host PRIVATE openenclave::oehost)

# Disposable debug key for simulation only; no production signing credentials.
add_custom_command(OUTPUT test-key.pem COMMAND ${OPENSSL_EXECUTABLE} genrsa
                                               -out test-key.pem -3 3072)

foreach (regression is_convertible_regression gcc13_release_regression
                    unordered_regression)
  add_executable(${regression}
                 enclave.cpp ${CMAKE_CURRENT_BINARY_DIR}/trusted/helloworld_t.c)
  target_include_directories(${regression}
                             PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/trusted)
  target_compile_definitions(
    ${regression}
    PRIVATE
      OE_API_VERSION=2
      REGRESSION_SOURCE="${CMAKE_CURRENT_SOURCE_DIR}/../enc/${regression}.cpp")
  target_compile_options(
    ${regression} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Werror>)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(
      ${regression} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wmaybe-uninitialized>)
  endif ()
  target_link_libraries(
    ${regression} PRIVATE openenclave::oeenclave openenclave::oecryptombedtls
                          openenclave::oelibcxx openenclave::oelibc)
  add_custom_command(
    OUTPUT ${regression}.signed
    COMMAND openenclave::oesign sign -e $<TARGET_FILE:${regression}> -c
            ${sample}/enclave/helloworld.conf -k test-key.pem
    DEPENDS ${regression} test-key.pem ${sample}/enclave/helloworld.conf)
  add_custom_target(sign_${regression} ALL DEPENDS ${regression}.signed)
  add_test(NAME ${regression}
           COMMAND consumer_host
                   ${CMAKE_CURRENT_BINARY_DIR}/${regression}.signed --simulate)
  set_tests_properties(
    ${regression} PROPERTIES TIMEOUT 60 PASS_REGULAR_EXPRESSION
                             "LIBCXX_CONSUMER_PASS")
endforeach ()
