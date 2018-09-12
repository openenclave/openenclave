# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(USE_LIBSGX)

# Install the attestation sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/make/attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install the remote_attestation sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/make/remote_attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )


else()

# Install the sort sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/make/sort
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

endif()

# Install the helloworld.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/make/helloworld
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install make file for samples folder.
install(FILES  ${CMAKE_CURRENT_LIST_DIR}/make/Makefile
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Samples assume that Clang is used, so skip testing otherwise.
if (CMAKE_C_COMPILER_ID MATCHES Clang)
    # for testing the samples, do an install to a local dir to build&run
    add_test(samples 
        sh ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.sh 
            -i ${PROJECT_BINARY_DIR} ${CMAKE_INSTALL_PREFIX}
            ${PROJECT_BINARY_DIR}/samples/samples-test)

    set(env_vars USE_LIBSGX=${USE_LIBSGX})

    set_property(TEST samples PROPERTY ENVIRONMENT "${env_vars}")
endif()