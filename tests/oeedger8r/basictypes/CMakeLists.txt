# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME edger8r_duplicated_size_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                     duplicated_size.edl)
set_tests_properties(
  edger8r_duplicated_size_warning
  PROPERTIES
  PASS_REGULAR_EXPRESSION
    "error: .*multiple size specifier"
)

add_test(NAME edger8r_duplicated_count_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                     duplicated_count.edl)
set_tests_properties(
  edger8r_duplicated_count_warning
  PROPERTIES
  PASS_REGULAR_EXPRESSION
    "error: .*multiple count specifier"
)
