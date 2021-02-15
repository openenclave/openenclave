# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# Both host-side stderr and stdout behave differently in Windows and Linux.
# Therefore, using corresponding oracle files for the test based on the type of OS.
if (WIN32)
  set(RESULTDIR ${CMAKE_CURRENT_SOURCE_DIR}/results/windows)
else ()
  set(RESULTDIR ${CMAKE_CURRENT_SOURCE_DIR}/results/others)
endif ()

# Use add_enclave_test to ensure the enclave binaries are copied from the pre-built directory
# when ADD_WINDOWS_ENCLAVE_TESTS is ON and BUILD_ENCLAVES is OFF.
add_enclave_test(tests/print print_host print_enc)

add_test(
  NAME tests/print-diff
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMAND
    ${OE_BASH} -c
    "OE_LOG_LEVEL=NONE host/print_host ./enc/print_enc >testout.stdout 2>testout.stderr &&
        diff ${RESULTDIR}/printhost.stdout testout.stdout &&
        diff ${RESULTDIR}/printhost.stderr testout.stderr")
