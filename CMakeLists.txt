#------------------------------------------------------------------------------
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

# allow simpler include() of our scripts
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# sanitize build type
string(TOUPPER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE)

enable_testing()
enable_language(ASM C CXX)

include(GNUInstallDirs)
set(OE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/output CACHE PATH "Path to the intermittent collector tree")
set(OE_BINDIR ${OE_OUTPUT_DIR}/bin CACHE PATH "Binary collector")
set(OE_INCDIR ${OE_OUTPUT_DIR}/include CACHE PATH "Include collector")
set(OE_LIBDIR ${OE_OUTPUT_DIR}/lib CACHE PATH "Library collector")

add_subdirectory(3rdparty)
add_subdirectory(enclave)
add_subdirectory(host)		# convertable to Windows
add_subdirectory(idl)
add_subdirectory(include)	# convertable to Windows
add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(tests)
add_subdirectory(tools)
