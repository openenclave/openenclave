# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME edger8r_string_attribute_error COMMAND edger8r ${EDGER8R_ARGS}
                                                     string_attribute.edl)
set_tests_properties(
  edger8r_string_attribute_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "invalid `string' attribute - `s' is not char pointer")

add_test(NAME edger8r_wstring_attribute_error COMMAND edger8r ${EDGER8R_ARGS}
                                                      wstring_attribute.edl)
set_tests_properties(
  edger8r_wstring_attribute_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "invalid `wstring' attribute - `s' is not wchar_t pointer")

add_test(NAME edger8r_string_out_error COMMAND edger8r ${EDGER8R_ARGS}
                                               string_out.edl)
set_tests_properties(
  edger8r_string_out_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "string/wstring attribute should be used with an `in' attribute")

add_test(NAME edger8r_string_usercheck_error COMMAND edger8r ${EDGER8R_ARGS}
                                                     string_usercheck.edl)
set_tests_properties(
  edger8r_string_usercheck_error
  PROPERTIES PASS_REGULAR_EXPRESSION
             "string/wstring attributes must be used with pointer direction")

add_test(NAME edger8r_string_count_error COMMAND edger8r ${EDGER8R_ARGS}
                                                 string_count.edl)
set_tests_properties(
  edger8r_string_count_error
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "size attributes are mutually exclusive with \\(w\\)string attribute")

add_test(NAME edger8r_string_size_error COMMAND edger8r ${EDGER8R_ARGS}
                                                string_size.edl)
set_tests_properties(
  edger8r_string_size_error
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "size attributes are mutually exclusive with \\(w\\)string attribute")

add_test(NAME edger8r_string_isary_error COMMAND edger8r ${EDGER8R_ARGS}
                                                 string_isary.edl)
set_tests_properties(
  edger8r_string_isary_error
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "`isary' attribute is only valid for user defined type, not for `char\\*'")

add_test(NAME edger8r_string_isptr_error COMMAND edger8r ${EDGER8R_ARGS}
                                                 string_isptr.edl)
set_tests_properties(
  edger8r_string_isptr_error
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "`isptr' attribute is only valid for user defined type, not for `char\\*'")

add_test(NAME edger8r_wstring_isptr_error COMMAND edger8r ${EDGER8R_ARGS}
                                                  wstring_isptr.edl)
set_tests_properties(
  edger8r_wstring_isptr_error
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "`isptr' attribute is only valid for user defined type, not for `wchar_t\\*'"
)

# oeedger8r does not support readonly attribute
add_test(NAME edger8r_string_readonly_error COMMAND edger8r ${EDGER8R_ARGS}
                                                    string_readonly.edl)
set_tests_properties(
  edger8r_string_readonly_error PROPERTIES PASS_REGULAR_EXPRESSION
                                           "unknown attribute: `readonly'")

add_test(NAME edger8r_wstring_readonly_error COMMAND edger8r ${EDGER8R_ARGS}
                                                     wstring_readonly.edl)
set_tests_properties(
  edger8r_wstring_readonly_error PROPERTIES PASS_REGULAR_EXPRESSION
                                            "unknown attribute: `readonly'")
