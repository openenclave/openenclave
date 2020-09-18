# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDGER8R_ARGS --header-only --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME edger8r_struct_deepcopy_01_warning
         COMMAND edger8r ${EDGER8R_ARGS} struct_deepcopy_01.edl)
set_tests_properties(
  edger8r_struct_deepcopy_01_warning
  PROPERTIES
    PASS_REGULAR_EXPRESSION
    "error: the structure declaration \"ms_t\" specifies a deep copy is expected. Referenced by value in function \"ecall\" detected"
)

# reopen after issue 3552 fix
#add_test(NAME edger8r_struct_deepcopy_02_warning COMMAND edger8r ${EDGER8R_ARGS}
#                                                   struct_deepcopy_02.edl)
#set_tests_properties(
#  edger8r_struct_deepcopy_02_warning
#  PROPERTIES
#  PASS_REGULAR_EXPRESSION
#  "error: the structure declaration \"ms_t\" specifies a deep copy, should not be used with an `out' attribute in function \"ecall\"")

# reopen after issue 3557 fix
#add_test(NAME edger8r_pointer_array_01_warning COMMAND edger8r ${EDGER8R_ARGS}
#                                                   pointer_array_01.edl)
#set_tests_properties(
#  edger8r_pointer_array_01_warning
#  PROPERTIES
#  PASS_REGULAR_EXPRESSION
#  "error: `ecall': Pointer array not allowed - `s' is a pointer array")

# reopen after issue 3557 fix
#add_test(NAME edger8r_pointer_array_02_warning COMMAND edger8r ${EDGER8R_ARGS}
#                                                   pointer_array_02.edl)
#set_tests_properties(
#  edger8r_pointer_array_02_warning
#  PROPERTIES
#  PASS_REGULAR_EXPRESSION
#  "error: `ecall': Pointer array not allowed - `s' is a pointer array")

# reopen after issue 3557 fix
#add_test(NAME edger8r_pointer_array_03_warning COMMAND edger8r ${EDGER8R_ARGS}
#                                                   pointer_array_03.edl)
#set_tests_properties(
#  edger8r_pointer_array_03_warning
#  PROPERTIES
#  PASS_REGULAR_EXPRESSION
#  "error: `ecall': Pointer array not allowed - `p' is a pointer array")

# reopen after issue 3557 fix
#add_test(NAME edger8r_pointer_array_04_warning COMMAND edger8r ${EDGER8R_ARGS}
#                                                   pointer_array_04.edl)
#set_tests_properties(
#  edger8r_pointer_array_04_warning
#  PROPERTIES
#  PASS_REGULAR_EXPRESSION
#  "error: `ecall': Pointer array not allowed - `p' is a pointer array")
