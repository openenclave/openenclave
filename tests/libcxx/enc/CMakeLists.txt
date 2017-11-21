# create a binary for each testcase listed in ../tests.supported

include(add_enclave_executable)
include(${CMAKE_CURRENT_LIST_DIR}/../../libc/get_testcase_name.cmake)

# helper lib to contain file needed by some tests
add_library(libcxxtest-support
	enc.cpp
	fuzzing.cpp
	memory_resource.cpp
	)
target_compile_options(libcxxtest-support PRIVATE
	-Wall -Werror
	-m64 -nostdinc -fPIC -fno-stack-protector
	$<$<COMPILE_LANGUAGE:CXX>:-std=c++14 -nostdinc++>
	)
target_link_libraries(libcxxtest-support PUBLIC oelibcxx)
target_link_libraries(libcxxtest-support INTERFACE -Wl,--undefined=Test)

# helper function to create enclave binary
function(add_libcxx_test_enc NAME CXXFILE)
	#message("libcxx-test NAME=${NAME} CXXFILE=${CXXFILE}")
	add_enclave_executable(libcxxtest-${NAME} sign.conf private.pem
		main.cpp
		)

	target_include_directories(libcxxtest-${NAME} PRIVATE
		..
		${CMAKE_SOURCE_DIR}/3rdparty/libcxx/libcxx/test
		${CMAKE_SOURCE_DIR}/3rdparty/libcxx/libcxx/test/support
		${CMAKE_SOURCE_DIR}/3rdparty/libcxx/libcxx/fuzzing
		)

	target_compile_options(libcxxtest-${NAME} PRIVATE -Wall)
	set_source_files_properties(enc.cpp PROPERTIES COMPILE_FLAGS -Werror)
	set_source_files_properties(main.cpp PROPERTIES COMPILE_DEFINITIONS WITH_MAIN)
	target_compile_definitions(libcxxtest-${NAME} PRIVATE -D__TEST__="${CXXFILE}")
	target_link_libraries(libcxxtest-${NAME} libcxxtest-support)
endfunction(add_libcxx_test_enc)

# iterate over the supported tests and create a binary for each.
file(STRINGS "../tests.supported" alltests)
foreach(testcase ${alltests})
        get_testcase_name(${testcase} name)
	add_libcxx_test_enc("${name}" "${testcase}")
endforeach(testcase)
