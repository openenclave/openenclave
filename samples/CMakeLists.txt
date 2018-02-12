# install the samples w/o this very CMakeLists.txt
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave
    PATTERN samples/CMakeLists.txt EXCLUDE
    )

# install a few of our own CMAKE files for the CMake samples
install(FILES
    ${PROJECT_SOURCE_DIR}/cmake/add_enclave_executable.cmake
    ${PROJECT_SOURCE_DIR}/cmake/compilersettings.cmake
    ${PROJECT_SOURCE_DIR}/cmake/oeidl_file.cmake
    DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples/cmake/cmake
    )

# for testing the samples, do an install to a local dir to build&run
add_test(samples sh ${CMAKE_CURRENT_SOURCE_DIR}/test-samples.sh -i ${PROJECT_BINARY_DIR} ${CMAKE_INSTALL_PREFIX} ${PROJECT_BINARY_DIR}/samples/samples-test)
