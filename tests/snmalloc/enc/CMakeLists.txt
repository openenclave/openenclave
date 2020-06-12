# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../snmalloc.edl)

add_custom_command(
  OUTPUT snmalloc_t.h snmalloc_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave_library(snmalloc_test_lib $<TARGET_OBJECTS:oesnmalloc>)

add_enclave(
  TARGET
  snmalloc_enc
  UUID
  e024b61f-8599-499d-bd83-b4b9da9dd389
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/snmalloc_t.c)

enclave_include_directories(snmalloc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(snmalloc_enc snmalloc_test_lib oelibc)

add_enclave(
  TARGET
  snmalloc_enc_link_error
  UUID
  e024b61f-8599-499d-bd83-b4b9da9dd388
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/snmalloc_t.c)

enclave_include_directories(snmalloc_enc_link_error PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
# Do not use pluggable allocator. This will result in multiple definition errors
# for dlmalloc functions.
enclave_link_libraries(snmalloc_enc_link_error oelibc)

# Exclude the enclave from build.
# From: https://stackoverflow.com/questions/30155619/expected-build-failure-tests-in-cmake
set_enclave_properties(snmalloc_enc_link_error PROPERTIES EXCLUDE_FROM_ALL TRUE
                       EXCLUDE_FROM_DEFAULT_BUILD TRUE)

add_test(
  NAME pluggable_allocators_expected_multiple_definition_error
  COMMAND ${CMAKE_COMMAND} --build . --target snmalloc_enc_link_error --config
          $<CONFIGURATION>
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

set_tests_properties(pluggable_allocators_expected_multiple_definition_error
                     PROPERTIES WILL_FAIL TRUE)
