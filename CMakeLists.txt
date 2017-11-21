#
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

# define project, take version from "VERSION" file
file(STRINGS "VERSION" OE_VERSION)
project("openenclave" VERSION ${OE_VERSION} LANGUAGES ASM C CXX)

# allow simpler include() of our scripts
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# set default build type and sanitize 
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug;Release;RelWithDebInfo")

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)
if(NOT DEFINED CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE})
	message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

# yes, we want tests
enable_testing()
# enable valgrind via "ctest -D ExperimentalMemCheck"
include(CTest)

# set default paths
include(GNUInstallDirs)
set(OE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/output CACHE PATH "Path to the intermittent collector tree")
set(OE_BINDIR ${OE_OUTPUT_DIR}/bin CACHE PATH "Binary collector")
set(OE_DATADIR ${OE_OUTPUT_DIR}/share CACHE PATH "Data collector root")
set(OE_DOCDIR ${OE_OUTPUT_DIR}/share/doc CACHE PATH "Doc collector root")
set(OE_INCDIR ${OE_OUTPUT_DIR}/include CACHE PATH "Include collector")
set(OE_LIBDIR ${OE_OUTPUT_DIR}/lib CACHE PATH "Library collector")

# generate config-file for using projects
include(gen_config_file)

# generate config for install
gen_config_file(${OE_DATADIR}/openenclave/config.mak "${CMAKE_INSTALL_PREFIX}")
install (FILES ${OE_DATADIR}/openenclave/config.mak DESTINATION ${CMAKE_INSTALL_DATADIR}/openenclave)

# finally, add all dirs that matter
add_subdirectory(3rdparty)
add_subdirectory(doc/refman)
add_subdirectory(enclave)
add_subdirectory(host)		# convertable to Windows
add_subdirectory(idl)
add_subdirectory(include)	# convertable to Windows
add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(samples)
add_subdirectory(tests)
add_subdirectory(tools)
