# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(print)
else()
add_subdirectory(enc)
add_subdirectory(host)

# note: this is Linux-specific
add_test(NAME tests/print
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND sh -c "host/print_host ./enc/print_enc.signed.so >testout.stdout 2>testout.stderr &&
        diff ${CMAKE_CURRENT_SOURCE_DIR}/print_host.stdout testout.stdout &&
        diff ${CMAKE_CURRENT_SOURCE_DIR}/print_host.stderr testout.stderr"
    )
endif()
