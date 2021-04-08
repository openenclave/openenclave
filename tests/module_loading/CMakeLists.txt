# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(module)
  add_subdirectory(module_negative_extra)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/module_loading module_loading_host module_loading_enc)

add_enclave_test(tests/module_loading_negative_extra module_loading_host
                 module_loading_negative_extra_enc)
set_enclave_tests_properties(
  tests/module_loading_negative_extra PROPERTIES PASS_REGULAR_EXPRESSION
  "Specifying more than one dependent .so module is unsupported")

# Bypass the test when the ADD_WINDOWS_ENCLAVE_TESTS is ON as the
# add_enclave_test assumes the enclave binary always under the enc/
# directory and therfore cannot locate module_loading_negative_path_enc
# (placed under enc/../)
if (NOT ADD_WINDOWS_ENCLAVE_TESTS)
  add_enclave_test(tests/module_loading_negative_path module_loading_host
                   module_loading_negative_path_enc)
  set_enclave_tests_properties(
    tests/module_loading_negative_path
    PROPERTIES
    PASS_REGULAR_EXPRESSION
    "Failed to locate the module. Please place the module under the same directory as the enclave binary."
  )
endif ()

add_enclave_test(tests/module_loading_negative_rpath module_loading_host
                 module_loading_negative_rpath_enc)
set_enclave_tests_properties(
  tests/module_loading_negative_rpath PROPERTIES PASS_REGULAR_EXPRESSION
  "RPATH or RUNPATH should not be used in the enclave binary")

add_enclave_test(tests/module_loading_negative_runpath module_loading_host
                 module_loading_negative_rpath_enc)
set_enclave_tests_properties(
  tests/module_loading_negative_runpath PROPERTIES PASS_REGULAR_EXPRESSION
  "RPATH or RUNPATH should not be used in the enclave binary")

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
if (BUILD_TYPE_UPPER STREQUAL "DEBUG" OR BUILD_TYPE_UPPER STREQUAL
                                         "RELWITHDEBINFO")
  if (UNIX)
    add_test(
      NAME oegdb-multi-module-test
      COMMAND
        ${OE_BINDIR}/oegdb --batch -nh # Do not use user's gdbinit
        --command=${CMAKE_CURRENT_SOURCE_DIR}/commands.gdb
        --return-child-result # This fails the test in case of any error.
        -arg host/module_loading_host enc/module_loading_enc)

  endif ()
endif ()
