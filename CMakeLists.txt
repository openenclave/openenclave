#------------------------------------------------------------------------------
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

include(GNUInstallDirs)

enable_language(C ASM)

set(OE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/output CACHE PATH "Path to the intermittent output tree")
set(OE_BINDIR ${OE_OUTPUT_DIR}/bin CACHE PATH "Binary collector")
set(OE_INCDIR ${OE_OUTPUT_DIR}/include CACHE PATH "Include collector")
set(OE_LIBDIR ${OE_OUTPUT_DIR}/lib CACHE PATH "Library collector")

add_subdirectory(enclave)
add_subdirectory(host)
add_subdirectory(include)
add_subdirectory(libc)
