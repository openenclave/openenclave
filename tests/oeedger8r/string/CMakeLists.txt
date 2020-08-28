# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME edger8r_string_attribute_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                       string_attribute.edl)
set_tests_properties(
  edger8r_string_attribute_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "Warning: Function 'ecall': wchar_t has different sizes on Windows and Linux. This enclave cannot be built in Linux and then safely loaded in Windows"
)

#reopen it after #3409 fix
#add_test(NAME edger8r_wstring_attribute_warning COMMAND edger8r ${EDGER8R_ARGS}
#                                                     wstring_attribute.edl)
#set_tests_properties(
#  edger8r_wstring_attribute_warning
#  PROPERTIES
#  PASS_REGULAR_EXPRESSION
#    "Warning: Function 'ecall': wchar_t has different sizes on Windows and Linux. This enclave cannot be built in Linux and then safely loaded in Windows"
#)

#reopen it after #3431 fix
#add_test(NAME edger8r_string_out_warning COMMAND edger8r ${EDGER8R_ARGS} string_out.edl)
#add_test(NAME edger8r_string_usercheck_warning COMMAND edger8r ${EDGER8R_ARGS} string_usercheck.edl)
#add_test(NAME edger8r_string_count_warning COMMAND edger8r ${EDGER8R_ARGS} string_count.edl)
#add_test(NAME edger8r_string_size_warning COMMAND edger8r ${EDGER8R_ARGS} string_size.edl)

add_test(NAME edger8r_string_isary_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                   string_isary.edl)
set_tests_properties(
  edger8r_string_isary_warning
  PROPERTIES PASS_REGULAR_EXPRESSION "error: .*expecting attribute got isary")

add_test(NAME edger8r_string_isptr_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                   string_isptr.edl)
set_tests_properties(
  edger8r_string_isptr_warning
  PROPERTIES PASS_REGULAR_EXPRESSION "error: .*expecting attribute got isptr")

add_test(NAME edger8r_wstring_isptr_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                    wstring_isptr.edl)
set_tests_properties(
  edger8r_wstring_isptr_warning
  PROPERTIES PASS_REGULAR_EXPRESSION "error: .*expecting attribute got isptr")

add_test(NAME edger8r_string_readonly_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                      string_readonly.edl)
set_tests_properties(
  edger8r_string_readonly_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "error: .*expecting attribute got readonly")

add_test(NAME edger8r_wstring_readonly_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                       wstring_readonly.edl)
set_tests_properties(
  edger8r_wstring_readonly_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "error: .*expecting attribute got readonly")
