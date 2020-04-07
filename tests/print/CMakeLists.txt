# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)

    #note: this is Linux-specific
    if (WIN32)
        set(RESULTDIR ${CMAKE_CURRENT_SOURCE_DIR}/results/windows)
    else()
        set(RESULTDIR ${CMAKE_CURRENT_SOURCE_DIR}/results/others)
    endif()

    add_test(NAME tests/print
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND sh -c "OE_LOG_LEVEL=NONE host/print_host ./enc/print_enc >testout.stdout 2>testout.stderr &&
            diff ${RESULTDIR}/printhost.stdout testout.stdout &&
            diff ${RESULTDIR}/printhost.stderr testout.stderr"
        )
else()

    add_enclave_test(tests/print print_host print_enc)
endif()
