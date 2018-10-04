include(ExternalProject)

ExternalProject_Add(tests_libc
    DOWNLOAD_COMMAND
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_LIST_DIR}/configure
            ${CMAKE_CURRENT_BINARY_DIR}/configure
        COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_LIST_DIR}/../tests.supported
            ${CMAKE_CURRENT_BINARY_DIR}/tests.supported
    CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_BINARY_DIR}
        ./configure
    BUILD_COMMAND
        COMMAND true
    INSTALL_COMMAND
        COMMAND true)
