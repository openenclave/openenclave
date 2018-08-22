# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(USE_LIBSGX)

# Install the attestation sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/make/attestation
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

else()

# Install the sort sample.
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/make/sort
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

endif()    

# Install make file for samples folder.
install(FILES  ${CMAKE_CURRENT_LIST_DIR}/make/Makefile
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples
    )

# for testing the samples, do an install to a local dir to build&run
add_test(samples 
    sh ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.sh 
        -i ${PROJECT_BINARY_DIR} ${CMAKE_INSTALL_PREFIX}
        ${PROJECT_BINARY_DIR}/samples/samples-test)

set_property(TEST samples PROPERTY ENVIRONMENT
    "USE_LIBSGX=${USE_LIBSGX};CC=${CMAKE_C_COMPILER};CXX=${CMAKE_CXX_COMPILER}")
