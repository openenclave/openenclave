# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

# define project, take version from "VERSION" file
file(STRINGS "VERSION" OE_VERSION)

option(ADD_WINDOWS_ENCLAVE_TESTS "Copy Linux binaries and Build windows enclave test" 0)
option(WND_BIN_DIR "Windows bianry files path" C:\\wind_build_oe)
option(LINUX_BIN_DIR "Linux binary files path" /home/vvdn/openenclave/linux_build_oe)
option(VS_CMAKE_TESTS_DIR "Direcotry to store both windows and linux binaries for Visual studio CMake tests" C:\\wnd_linux_build_oe)

# Select the assembler
if (UNIX)
  set(OE_ASM ASM)
elseif(WIN32)
  set(OE_ASM ASM_MASM)
endif()

project("openenclave" VERSION ${OE_VERSION} LANGUAGES ${OE_ASM} C CXX)

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
install(FILES ${OE_DATADIR}/openenclave/config.mak DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave)

# generate & install CMake Export file for other projects using CMAKE
install(EXPORT openenclave DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave)

# cpack package handling
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "OpenEnclave SDK")
set(CPACK_PACKAGE_CONTACT "openenclave@microsoft.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION ${OE_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
include(CPack)

# finally, add all dirs that matter
add_subdirectory(host)		# convertable to Windows
add_subdirectory(include)	# convertable to Windows
if (UNIX)
add_subdirectory(3rdparty)
add_subdirectory(doc/refman)
add_subdirectory(enclave)
add_subdirectory(idl)
add_subdirectory(debugger)
add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(samples)
add_subdirectory(tests)
add_subdirectory(tools)
endif()

if(WIN32)
add_subdirectory(tests/echo/host)
add_subdirectory(tests/ecall/host)
add_subdirectory(tests/mem)
add_subdirectory(tests/str)

if(ADD_WINDOWS_ENCLAVE_TESTS)
add_subdirectory(tests/windows)
else()
Message("ADD_WINDOWS_ENCLAVE_TESTS - Not set, Tests directory ommited.")
endif()

endif()
