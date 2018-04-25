# Use an external project to place the binaries that you need to copy
# from Linux to their target windows build folders.

if(ADD_WINDOWS_ENCLAVE_TESTS)

# Copy Linux project binaries from WSL build location to Windows build location.
include (ExternalProject)

ExternalProject_Add(linux_binaries_include
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""#${CMAKE_COMMAND} -E copy_directory ${LINUX_BIN_DIR}/ ${CMAKE_BINARY_DIR}/wsl_bin
	COMMAND ""
	INSTALL_COMMAND ""
    )

# Copy all the .exe files in single directory
file(GLOB_RECURSE WINDOWS_EXE_FILES ${CMAKE_BINARY_DIR}/*.exe)
file(COPY ${WINDOWS_EXE_FILES} DESTINATION ${CMAKE_BINARY_DIR}/wnd_exes)

# Copy all the signed so files in single directory in windows build folder.
file(GLOB_RECURSE LINUX_SIGNED_FILES ${LINUX_BIN_DIR}/*.signed.so)
file(COPY ${LINUX_SIGNED_FILES} DESTINATION ${CMAKE_BINARY_DIR}/wsl_bin)


# call a function which will add tests for the each project entries.
#include(add_wnd_enclave_tests)
#add_wnd_enclave_tests(${CMAKE_BINARY_DIR}/wnd_exes ${CMAKE_BINARY_DIR}/wsl_bin)

endif()