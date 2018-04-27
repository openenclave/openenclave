# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Top-level CMake file for OpenEnclave.
#
cmake_minimum_required(VERSION 3.5.1)

# define project, take version from "VERSION" file
file(STRINGS "VERSION" OE_VERSION)

option(ADD_WINDOWS_ENCLAVE_TESTS "Copy Linux binaries and Build windows enclave test" 0)
option(WND_BIN_DIR "Windows bianry files path" C:\\wnd_build_oe)
option(LINUX_BIN_DIR "Linux binary files path" /home/vvdn/openenclave/linux_build_oe)

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
add_subdirectory(debugger)
add_subdirectory(enclave)
add_subdirectory(enclave/core)
add_subdirectory(idl)
add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(samples)
add_subdirectory(tests)
add_subdirectory(tools)
endif()

if(WIN32)


# If add windows enclave tests is set, add tests/windows directory.
if(ADD_WINDOWS_ENCLAVE_TESTS)
#add_subdirectory(tests/abortStatus)	build failed, see abortstatus_build_failed_log.txt
add_subdirectory(tests/aesm)			#PASSED just added in top level CMakeLists.txt file, no change in tests/aesm/CMakeLists.txt.
add_subdirectory(tests/cppException)	#PASSED
add_subdirectory(tests/ecall)#/host)	#PASSED
#add_subdirectory(tests/ecall_ocall)	test throws exception, see ecall_ocall_exception_screenshot.png
add_subdirectory(tests/echo)#/host)		#PASSED
#add_subdirectory(tests/eenter)			!!!!!!!!does not contain a CMakeLists.txt file.
#add_subdirectory(tests/file)			build failed, see tests_file_build_failed_log.txt
#add_subdirectory(tests/hashstr)		!!!!!!!!does not contain a CMakeLists.txt file.
add_subdirectory(tests/hostcalls)		#PASSED
#add_subdirectory(tests/libc)			slash is not allowed in name, long path name error, see libs_long_path_error.png
#add_subdirectory(tests/libcxx)			Linux-Debug compilation failed, see libcxx_linux_debug_failed_log.txt
add_subdirectory(tests/load)			#PASSED just added in top level CMakeLists.txt file, no change in tests/load/CMakeLists.txt.
#add_subdirectory(tests/mbed)			Throws exception File : host.c Line No. 82 this function throws exception(inside call.c line no. 217)
#add_subdirectory(tests/measure)		!!!!!!!!does not contain a CMakeLists.txt file.
add_subdirectory(tests/mem)				#PASSED
#add_subdirectory(tests/NestedCall)     Throws exception Integer division by zero File: host.c Line No. 146 (with i = 2, which in turns throws exception at line no. : 50)
#add_subdirectory(tests/ocall)			build failed, see ocall_build_failed_log.png
#add_subdirectory(tests/ocall-restrict) build failed, see ocall_restrict_build_failed_log.png
#add_subdirectory(tests/pingpong)		build failed, see pingpong_build_failed_log.txt
add_subdirectory(tests/print)			#PASSED
add_subdirectory(tests/report)			#PASSED
#add_subdirectory(tests/ricochet)		test failed, see ricochet_test_failed_log.txt
#add_subdirectory(tests/SampleApp)		can't add because directory structure is different (host & enc folders are missing)
#add_subdirectory(tests/SampleAppCRT)	can't add because directory structure is different (host & enc folders are missing)
#add_subdirectory(tests/stdc)			test failed, see stdc_test_failed_log.txt
add_subdirectory(tests/stdcxx)			#PASSED
add_subdirectory(tests/str)				#PASSED
#add_subdirectory(tests/tester)			build failed, see tester_build_failed_log.txt
#add_subdirectory(tests/thread)			build failed, see thread_build_failed_log.txt
#add_subdirectory(tests/typeinfo)		don't have .so file, build failed, see typeinfo_build_failed_log.txt
#add_subdirectory(tests/VectorException) build failed, see vectorexception_build_failed_log.txt

#add_subdirectory(tests/windows)

else()

#add_subdirectory(tests/abortStatus)
add_subdirectory(tests/aesm)
add_subdirectory(tests/cppException/host)
add_subdirectory(tests/ecall/host)
#add_subdirectory(tests/ecall_ocall/host)
add_subdirectory(tests/echo/host)
#add_subdirectory(tests/eenter)
#add_subdirectory(tests/file/host)
#add_subdirectory(tests/hashstr)
add_subdirectory(tests/hostcalls/host)
#add_subdirectory(tests/libc/host)
#add_subdirectory(tests/libcxx/host)
add_subdirectory(tests/load)
#add_subdirectory(tests/mbed/host)
#add_subdirectory(tests/measure)
add_subdirectory(tests/mem)
#add_subdirectory(tests/NestedCall/host)
#add_subdirectory(tests/ocall/host)
#add_subdirectory(tests/ocall-restrict/host)
#add_subdirectory(tests/pingpong/host)
add_subdirectory(tests/print/host)
add_subdirectory(tests/report/host)
#add_subdirectory(tests/ricochet/host)
#add_subdirectory(tests/SampleApp)
#add_subdirectory(tests/SampleAppCRT)
#add_subdirectory(tests/stdc)
add_subdirectory(tests/stdcxx/host)
add_subdirectory(tests/str)
#add_subdirectory(tests/tester/host)
#add_subdirectory(tests/thread/host)
#add_subdirectory(tests/typeinfo)
#add_subdirectory(tests/VectorException)

Message("ADD_WINDOWS_ENCLAVE_TESTS - Not set, Tests directory ommited.")
endif()

endif()
