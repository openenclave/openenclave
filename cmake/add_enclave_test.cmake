# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


## This function is to add test for given host file and enclave file.
## TEST_NAME	: test name for add test.
## HOST_FILE	: Host application executable file name.
## ENC_FILE 	: Signed/Unsigned enclave file name.

function(add_enclave_test TEST_NAME HOST_FILE ENC_FILE)

    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${HOST_FILE}> $<TARGET_FILE:${ENC_FILE}> ${ARGN})

endfunction(add_enclave_test)
