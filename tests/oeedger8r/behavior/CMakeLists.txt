# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# TODO: Check exit code of edger8r. Unfortunately, the `WILL_FAIL`
# property does not combine well with the regular expression checks,
# so we're preferring those for now.
add_test(NAME edger8r_private_trusted_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                      private_trusted.edl)
set_tests_properties(
  edger8r_private_trusted_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "error: Function `private': `private' specifier is not supported by oeedger8r"
)

# `allow` in an ECALL should cause an error.
add_test(NAME edger8r_allow_list_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                 allow_list.edl)
set_tests_properties(
  edger8r_allow_list_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "error: .* the `allow' syntax is invalid for a trusted function .ECALL.")

# These need to be separate tests to ensure that each type, for both
# trusted and untrusted functions, generate the appropriate warning,
# but we can reuse the EDL file.
add_test(NAME edger8r_portability_trusted_wchar_t_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_trusted_wchar_t_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ocall': `wchar_t' has different sizes")

add_test(NAME edger8r_portability_trusted_long_double_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_trusted_long_double_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ocall': `long double' has different sizes")

add_test(NAME edger8r_portability_trusted_long_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_trusted_long_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ocall': `long' has different sizes")

add_test(NAME edger8r_portability_trusted_unsigned_long_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_trusted_unsigned_long_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ocall': `unsigned long' has different sizes")

add_test(NAME edger8r_portability_untrusted_wchar_t_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_untrusted_wchar_t_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ecall': `wchar_t' has different sizes")

add_test(NAME edger8r_portability_untrusted_long_double_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_untrusted_long_double_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ecall': `long double' has different sizes")

add_test(NAME edger8r_portability_untrusted_long_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_untrusted_long_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ecall': `long' has different sizes")

add_test(NAME edger8r_portability_untrusted_unsigned_long_warning
         COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(
  edger8r_portability_untrusted_unsigned_long_warning
  PROPERTIES PASS_REGULAR_EXPRESSION
             "Function `ecall': `unsigned long' has different sizes")

# Test signedness of size and count
add_test(NAME edger8r_size_signedness_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                      size_signedness.edl)
set_tests_properties(
  edger8r_size_signedness_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "warning: .* Function `signed_size': The size or count parameter `size' should not be signed \\[-Wsigned-size-or-count\\]."
    FAIL_REGULAR_EXPRESSION
    "warning: .* Function `unsigned_size': The size or count parameter `size' should not be signed \\[-Wsigned-size-or-count\\]."
)

add_test(NAME edger8r_count_signedness_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                       count_signedness.edl)
set_tests_properties(
  edger8r_count_signedness_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "warning: .* Function `signed_count': The size or count parameter `count' should not be signed \\[-Wsigned-size-or-count\\]."
    FAIL_REGULAR_EXPRESSION
    "warning: .* Function `unsigned_count': The size or count parameter `count' should not be signed \\[-Wsigned-size-or-count\\]."
)

add_test(NAME edger8r_size_and_count_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                     size_and_count.edl)
set_tests_properties(
  edger8r_size_and_count_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "Function `size_and_count': simultaneous `size' and `count' parameters `size' and `count' are not supported by oeedger8r."
)

add_test(NAME edger8r_deepcopy_value_warning COMMAND edger8r ${EDGER8R_ARGS}
                                                     deepcopy_value.edl)
set_tests_properties(
  edger8r_deepcopy_value_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "error: the structure declaration `MyStruct' specifies a deep copy is expected. Referenced by value in function `deepcopy_value' detected."
)
