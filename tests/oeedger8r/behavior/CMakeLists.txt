# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# TODO: Check exit code of edger8r. Unfortunately, the `WILL_FAIL`
# property does not combine well with the regular expression checks,
# so we're preferring those for now.
add_test(NAME edger8r_private_trusted_warning COMMAND edger8r ${EDGER8R_ARGS} private_trusted.edl)
set_tests_properties(edger8r_private_trusted_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "error: Function 'private': 'private' specifier is not supported by oeedger8r")

add_test(NAME edger8r_allow_list_warning COMMAND edger8r ${EDGER8R_ARGS} allow_list.edl)
set_tests_properties(edger8r_allow_list_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Warning: Function 'ocall_allow': Reentrant ocalls are not supported by Open Enclave. Allow list ignored.")

# NOTE: These are two separate tests because the edger8r exits as soon
# as the first instance is found.
add_test(NAME edger8r_switchless_trusted_warning COMMAND edger8r ${EDGER8R_ARGS} switchless_trusted.edl)
set_tests_properties(edger8r_switchless_trusted_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "error: Function 'switchless': switchless ecalls and ocalls are not yet supported by Open Enclave SDK.")

add_test(NAME edger8r_switchless_untrusted_warning COMMAND edger8r ${EDGER8R_ARGS} switchless_untrusted.edl)
set_tests_properties(edger8r_switchless_untrusted_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "error: Function 'switchless': switchless ecalls and ocalls are not yet supported by Open Enclave SDK.")

# These need to be separate tests to ensure that each type, for both
# trusted and untrusted functions, generate the appropriate warning,
# but we can reuse the EDL file.
add_test(NAME edger8r_portability_trusted_wchar_t_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_trusted_wchar_t_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ocall': wchar_t has different sizes")

add_test(NAME edger8r_portability_trusted_long_double_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_trusted_long_double_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ocall': long double has different sizes")

add_test(NAME edger8r_portability_trusted_long_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_trusted_long_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ocall': long has different sizes")

add_test(NAME edger8r_portability_trusted_unsigned_long_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_trusted_unsigned_long_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ocall': unsigned long has different sizes")

add_test(NAME edger8r_portability_untrusted_wchar_t_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_untrusted_wchar_t_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ecall': wchar_t has different sizes")

add_test(NAME edger8r_portability_untrusted_long_double_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_untrusted_long_double_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ecall': long double has different sizes")

add_test(NAME edger8r_portability_untrusted_long_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_untrusted_long_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ecall': long has different sizes")

add_test(NAME edger8r_portability_untrusted_unsigned_long_warning COMMAND edger8r ${EDGER8R_ARGS} portability.edl)
set_tests_properties(edger8r_portability_untrusted_unsigned_long_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "Function 'ecall': unsigned long has different sizes")
