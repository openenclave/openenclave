# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(test_oesignlib test-oesignlib.c)

target_link_libraries(test_oesignlib oesignlib oehostmr)

# Exclude the target from build
# From: https://stackoverflow.com/questions/30155619/expected-build-failure-tests-in-cmake
set_target_properties(test_oesignlib PROPERTIES EXCLUDE_FROM_ALL TRUE
                                                EXCLUDE_FROM_DEFAULT_BUILD TRUE)

# Exercise the library linking
add_test(
  NAME test_link_oesignlib
  COMMAND ${CMAKE_COMMAND} --build . --target test_oesignlib --config
          $<CONFIGURATION>
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
