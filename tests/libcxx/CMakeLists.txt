# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../libc/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)
foreach(testcase ${alltests})
	get_testcase_name(${testcase} name)
	add_test(tests/libcxx/${name} sh -c "host/libcxxhost ./enc/libcxxtest-${name}.signed.so")
endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)
