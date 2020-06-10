# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# Helper function to obtain name for a test-case. Given a filename, chop
# extension, dir-prefix, and replace special chars.
#
# Usage:
#
#       get_testcase_name(<filename> <namevar>)
#
# Arguments:
# filename - filename containing the test
# namevar - variable to receive the testcase name
#
function (get_testcase_name FILENAME NAMEVAR PREFIX)
  string(REGEX REPLACE "\.c(pp)?$" "" n ${FILENAME})
  if (NOT PREFIX STREQUAL "")
    string(REGEX REPLACE ${PREFIX} "" n ${n})
  endif ()
  string(REGEX REPLACE "[/=]" "_" n ${n})
  string(REGEX REPLACE "[\!]" "-" n ${n})
  string(REGEX REPLACE "[\[]" "__" n ${n})
  string(REGEX REPLACE "[\]]" "__" n ${n})

  # Encrypted filesystems on Linux have a smaller limit on the
  # maximum file name length. Limit the testcase name to the
  # last 120 characters.
  set(max_length 120)
  string(LENGTH ${n} n_length)
  if (n_length GREATER max_length)
    math(EXPR start_pos "${n_length} - ${max_length}")
    string(SUBSTRING ${n} ${start_pos} ${max_length} n)
  endif ()

  set(${NAMEVAR}
      ${n}
      PARENT_SCOPE)
endfunction (get_testcase_name)
