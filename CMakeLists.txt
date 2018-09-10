# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

# define project, take version from "VERSION" file
file(STRINGS "VERSION" OE_VERSION)

option(ADD_WINDOWS_ENCLAVE_TESTS "Copy Linux binaries to windows build directory and Build windows enclave test" 0)

# Select the assembler
if (UNIX)
  set(OE_ASM ASM)
elseif(WIN32)
  set(OE_ASM ASM_MASM)
endif()

# set default Jenkins variables
if (NOT GIT_BRANCH)
    set(GIT_BRANCH "null")
endif(NOT GIT_BRANCH)
if (NOT GIT_COMMIT)
    set(GIT_COMMIT "null")
endif(NOT GIT_COMMIT)
if (NOT BUILD_NUMBER)
    set(BUILD_NUMBER "0")
endif(NOT BUILD_NUMBER)

project("open-enclave" VERSION ${OE_VERSION} LANGUAGES ${OE_ASM} C CXX)

# allow simpler include() of our scripts
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(compilersettings)

# yes, we want tests
enable_testing()
# enable valgrind via "ctest -D ExperimentalMemCheck"
include(CTest)

# set default paths
include(GNUInstallDirs)
set(OE_OUTPUT_DIR ${PROJECT_BINARY_DIR}/output CACHE INTERNAL "Path to the intermittent collector tree")
set(OE_BINDIR ${OE_OUTPUT_DIR}/bin CACHE INTERNAL "Binary collector")
set(OE_DATADIR ${OE_OUTPUT_DIR}/share CACHE INTERNAL "Data collector root")
set(OE_DOCDIR ${OE_OUTPUT_DIR}/share/doc CACHE INTERNAL "Doc collector root")
set(OE_INCDIR ${OE_OUTPUT_DIR}/include CACHE INTERNAL "Include collector")
set(OE_LIBDIR ${OE_OUTPUT_DIR}/lib CACHE INTERNAL "Library collector")

# generate config-file for other projects using Makefile
include(gen_config_file)
gen_config_file(${OE_DATADIR}/openenclave/config.mak "${CMAKE_INSTALL_PREFIX}")
install(FILES ${OE_DATADIR}/openenclave/config.mak DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave/samples)
install(FILES ${OE_DATADIR}/openenclave/config.mak DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave)

# generate & install CMake Export file for other projects using CMAKE
include(CMakePackageConfigHelpers)
configure_package_config_file(
    cmake/openenclave-config.cmake.in
    ${CMAKE_BINARY_DIR}/cmake/openenclave-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
)
write_basic_package_version_file(
    ${CMAKE_BINARY_DIR}/cmake/openenclave-config-version.cmake
    COMPATIBILITY SameMajorVersion)
install(
    FILES ${CMAKE_BINARY_DIR}/cmake/openenclave-config.cmake
          ${CMAKE_BINARY_DIR}/cmake/openenclave-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
)
install(
    EXPORT openenclave-targets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
    FILE openenclave-targets.cmake
)

# cpack package handling
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Enclave SDK")
set(CPACK_PACKAGE_CONTACT "openenclave@microsoft.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsgx-enclave-common (>=1.0.101.45575-1.0), libsgx-enclave-common-dev (>=1.0.101.45575-1.0), libsgx-ngsa-ql (>=1.0.101.45575-1.0), libsgx-ngsa-ql-dev (>=1.0.101.45575-1.0)")
include(CPack)

# define build options that affect cmake across multiple subdirectories
option(USE_LIBSGX "Build oehost using SGX library requiring FLC" OFF)
if (USE_LIBSGX AND WIN32)
message(FATAL_ERROR "USE_LIBSGX is not supported on Windows. Disable this when calling cmake with -DUSE_LIBSGX=OFF")
endif()

option(USE_DEBUG_MALLOC "Build oehost using SGX library requiring FLC" OFF)
if (USE_DEBUG_MALLOC AND WIN32)
message(FATAL_ERROR "USE_DEBUG_MALLOC is not supported on Windows. Disable this when calling cmake with -DUSE_DEBUG_MALLOC=OFF")
endif()

include(add_enclave_test)

# finally, add all dirs that matter
add_subdirectory(host)		# convertable to Windows
add_subdirectory(include)	# convertable to Windows
add_subdirectory(tests)
if (UNIX)
add_subdirectory(3rdparty)
add_subdirectory(debugger)
add_subdirectory(docs/refman)
add_subdirectory(enclave)
add_subdirectory(enclave/core)
add_subdirectory(idl)
add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(samples)
add_subdirectory(tools)
endif()
