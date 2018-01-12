#
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

# Use ML64 as assembler on Windows
if (WIN32)
set(CMAKE_ASM_MASM_COMPILER "ml64")
endif()

# define project, take version from "VERSION" file
file(STRINGS "VERSION" OE_VERSION)

if (UNIX)
project("openenclave" VERSION ${OE_VERSION} LANGUAGES ASM C CXX)
elseif (WIN32)
project("openenclave" VERSION ${OE_VERSION} LANGUAGES ASM_MASM C CXX)
endif()

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

# generate config-file for using projects
include(gen_config_file)

# generate config for install
gen_config_file(${OE_DATADIR}/openenclave/config.mak "${CMAKE_INSTALL_PREFIX}")
install (FILES ${OE_DATADIR}/openenclave/config.mak DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave)

# finally, add all dirs that matter
add_subdirectory(host)		# convertable to Windows
add_subdirectory(include)	# convertable to Windows
if (UNIX)
add_subdirectory(3rdparty)
add_subdirectory(doc/refman)
add_subdirectory(enclave)
add_subdirectory(idl)
add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(samples)
add_subdirectory(tests)
add_subdirectory(tools)
endif()

if(WIN32)
add_subdirectory(tests/echo/host)
endif()
