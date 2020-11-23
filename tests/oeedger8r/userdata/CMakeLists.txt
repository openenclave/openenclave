# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME edger8r_string_usertype_error COMMAND edger8r ${EDGER8R_ARGS}
                                                    string_usertype.edl)
set_tests_properties(
  edger8r_string_usertype_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "invalid `string' attribute - `p1' is not char pointer")

add_test(NAME edger8r_usercheck_count_error COMMAND edger8r ${EDGER8R_ARGS}
                                                    usercheck_count.edl)
set_tests_properties(
  edger8r_usercheck_count_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "size/count attributes must be used with pointer direction")

add_test(NAME edger8r_usercheck_size_error COMMAND edger8r ${EDGER8R_ARGS}
                                                   usercheck_size.edl)
set_tests_properties(
  edger8r_usercheck_size_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "size/count attributes must be used with pointer direction")
