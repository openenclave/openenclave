# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(USE_LIBSGX)

# Install the remote_attestation sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/remote_attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install the local_attestation sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/local_attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

endif()

# Install the helloworld sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/helloworld
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install the file-encryptor sample
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/file-encryptor
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install the data-sealing sample
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/data-sealing
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install make file for samples folder.
install(FILES  ${CMAKE_CURRENT_LIST_DIR}/Makefile
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# Install README.md file for samples folder.
install(FILES  ${CMAKE_CURRENT_LIST_DIR}/README.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# for testing the samples, do an install to a local dir to build&run
add_test(samples
    sh ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.sh
        -i ${PROJECT_BINARY_DIR} ${CMAKE_INSTALL_PREFIX}
        ${PROJECT_BINARY_DIR}/samples/samples-test)

set(env_vars USE_LIBSGX=${USE_LIBSGX})

set_property(TEST samples PROPERTY ENVIRONMENT "${env_vars}")
