# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

option(ENABLE_FULL_LIBC_TESTS "Build all libc tests and include in test list" OFF)
option(ENABLE_FULL_LIBCXX_TESTS "Build all libcxx tests and include in test list" OFF)

if(ENABLE_FULL_LIBC_TESTS)
    message("ENABLE_FULL_LIBC_TESTS set - building all libc tests")
else()
    message("ENABLE_FULL_LIBC_TESTS not set - building some libc tests")
endif()

if(ENABLE_FULL_LIBCXX_TESTS)
    message("ENABLE_FULL_LIBCXX_TESTS set - building all libcxx tests")
else()
    message("ENABLE_FULL_LIBCXX_TESTS not set - building some libcxx tests")
endif()

if (UNIX)

add_subdirectory(abortStatus)
add_subdirectory(aesm)
add_subdirectory(crypto)
add_subdirectory(ecall)
add_subdirectory(ecall_ocall)
add_subdirectory(echo)
add_subdirectory(cppException)
add_subdirectory(file)
add_subdirectory(hostcalls)
add_subdirectory(hexdump)

add_subdirectory(libc)
add_subdirectory(libcxx)
add_subdirectory(load)
add_subdirectory(mbed)
add_subdirectory(mem)
add_subdirectory(NestedCall)
add_subdirectory(ocall)
add_subdirectory(ocall-alloc)
add_subdirectory(ocall-restrict)
add_subdirectory(pingpong)
add_subdirectory(pingpong-shared)
add_subdirectory(print)
add_subdirectory(props)
add_subdirectory(report)
add_subdirectory(ricochet)
add_subdirectory(SampleApp)
add_subdirectory(SampleAppCRT)
add_subdirectory(sealKey)
add_subdirectory(stdc)
add_subdirectory(stdcxx)
add_subdirectory(str)
add_subdirectory(tester)
add_subdirectory(thread)
add_subdirectory(typeinfo)
add_subdirectory(VectorException)

endif()

if (WIN32)

# WINDOWS : add following tests only if ADD_WINDOWS_ENCLAVE_TESTS is set.
if(ADD_WINDOWS_ENCLAVE_TESTS)

#add_subdirectory(abortStatus)		build failed, see abortstatus_build_failed_log.txt
add_subdirectory(aesm)				#PASSED just added in top level CMakeLists.txt file, no change in aesm/CMakeLists.txt.
add_subdirectory(cppException)		#PASSED
add_subdirectory(ecall)#/host)		#PASSED
#add_subdirectory(ecall_ocall)		test throws exception, see ecall_ocall_exception_screenshot.png
add_subdirectory(echo)#/host)		#PASSED
#add_subdirectory(eenter)			!!!!!!!!does not contain a CMakeLists.txt file.
#add_subdirectory(file)				build failed, see tests_file_build_failed_log.txt
add_subdirectory(hexdump)			#PASSED
#add_subdirectory(hashstr)			!!!!!!!!does not contain a CMakeLists.txt file.
add_subdirectory(hostcalls)			#PASSED
#add_subdirectory(libc)				slash is not allowed in name, long path name error, see libs_long_path_error.png
#add_subdirectory(libcxx)			Linux-Debug compilation failed, see libcxx_linux_debug_failed_log.txt
add_subdirectory(load)				#PASSED just added in top level CMakeLists.txt file, no change in load/CMakeLists.txt.
#add_subdirectory(mbed)				Throws exception File : host.c Line No. 82 this function throws exception(inside call.c line no. 217)
#add_subdirectory(measure)			!!!!!!!!does not contain a CMakeLists.txt file.
add_subdirectory(mem)				#PASSED
#add_subdirectory(NestedCall)		Throws exception Integer division by zero File: host.c Line No. 146 (with i = 2, which in turns throws exception at line no. : 50)
#add_subdirectory(ocall)			build failed, see ocall_build_failed_log.png
add_subdirectory(ocall-alloc)		#PASSED
#add_subdirectory(ocall-restrict)	build failed, see ocall_restrict_build_failed_log.png
#add_subdirectory(pingpong)			build failed, see pingpong_build_failed_log.txt
#add_subdirectory(pingpong-shared)	error
add_subdirectory(print)				#PASSED
#add_subdirectory(props)			signed/unsigned test needs to be mentioned in add_test, implementation checks argc, where it failed.
add_subdirectory(report)			#PASSED
#add_subdirectory(ricochet)			test failed, see ricochet_test_failed_log.txt
#add_subdirectory(SampleApp)		can't add because directory structure is different (host & enc folders are missing)
#add_subdirectory(SampleAppCRT)		can't add because directory structure is different (host & enc folders are missing)
add_subdirectory(sealKey)			#PASSED
#add_subdirectory(stdc)				test failed, see stdc_test_failed_log.txt
add_subdirectory(stdcxx)			#PASSED
add_subdirectory(str)				#PASSED
#add_subdirectory(tester)			build failed, see tester_build_failed_log.txt
#add_subdirectory(thread)			build failed, see thread_build_failed_log.txt
#add_subdirectory(typeinfo)			don't have .so file, build failed, see typeinfo_build_failed_log.txt
#add_subdirectory(VectorException)	build failed, see vectorexception_build_failed_log.txt

else()

#add_subdirectory(abortStatus)
add_subdirectory(aesm)
add_subdirectory(cppException/host)
add_subdirectory(ecall/host)
#add_subdirectory(ecall_ocall/host)
add_subdirectory(echo/host)
#add_subdirectory(eenter)
#add_subdirectory(file/host)
add_subdirectory(hexdump/host)
#add_subdirectory(hashstr)
add_subdirectory(hostcalls/host)
#add_subdirectory(libc/host)
#add_subdirectory(libcxx/host)
add_subdirectory(load)
#add_subdirectory(mbed/host)
#add_subdirectory(measure)
add_subdirectory(mem)
#add_subdirectory(NestedCall/host)
#add_subdirectory(ocall/host)
add_subdirectory(ocall-alloc/host)
#add_subdirectory(ocall-restrict/host)
#add_subdirectory(pingpong/host)
#add_subdirectory(pingpong-shared/host)
add_subdirectory(print/host)
#add_subdirectory(props/host)
add_subdirectory(report/host)
#add_subdirectory(ricochet/host)
#add_subdirectory(SampleApp)
#add_subdirectory(SampleAppCRT)
add_subdirectory(sealKey/host)
#add_subdirectory(stdc)
add_subdirectory(stdcxx/host)
add_subdirectory(str)
#add_subdirectory(tester/host)
#add_subdirectory(thread/host)
#add_subdirectory(typeinfo)
#add_subdirectory(VectorException)

endif()#ADD_WINDOWS_ENCLAVE_TESTS

endif() #WIN32
