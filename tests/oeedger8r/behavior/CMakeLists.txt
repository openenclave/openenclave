# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# TODO: Check exit code of edger8r. Unfortunately, the `WILL_FAIL`
# property does not combine well with the regular expression checks,
# so we're preferring those for now.
add_test(NAME edger8r_private_trusted_warning COMMAND edger8r ${EDGER8R_ARGS} private_trusted.edl)
set_tests_properties(edger8r_private_trusted_warning PROPERTIES
  PASS_REGULAR_EXPRESSION "error: Function 'private': 'private' specifier is not supported by oeedger8r")
