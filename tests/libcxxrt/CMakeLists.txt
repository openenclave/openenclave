# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

file(STRINGS "tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "")

    if("${name}" STREQUAL "test_foreign_exceptions")
        add_enclave_test(tests/libcxxrt/${name} libcxxrt_host libcxxrttest-${name}_enc)
    else()
        if (UNIX)
            # On Unix, building each test into a executable on the host that is linked against the default system
            # libraries, then run the executable to produce the expected output log for that test. The log from the
            # equivalent enclave test binary will be compared against it.
            add_executable(${name} enc/${name}.cpp)
            target_compile_options(${name} PRIVATE -Wno-error)

            # Generate expected output with system-test.
            add_custom_target(test-expected-${name}-output ALL
                COMMAND ${name} > ${PROJECT_BINARY_DIR}/tests/libcxxrt/exp_${name}_output.log 2>&1
                DEPENDS ${name})

            set(RESULTDIR ${CMAKE_CURRENT_BINARY_DIR})
        else()
            # On Windows, the test cannot be directly compiled on the host (with the cl compiler).
            # Instead, comparing the output of each test against the pre-generated output file.
            set(RESULTDIR ${CMAKE_CURRENT_SOURCE_DIR}/results)
        endif()

        # Use add_enclave_test to ensure the enclave binaries are copied from the pre-built directory
        # when ADD_WINDOWS_ENCLAVE_TESTS is ON and BUILD_ENCLAVES is OFF.
        add_enclave_test(tests/libcxxrt/${name} libcxxrt_host libcxxrttest-${name}_enc)

        # Run the enclave test and compare its output against the expected one.
        add_test(NAME tests/libcxxrt/${name}-diff
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMAND ${OE_BASH} -c "./host/libcxxrt_host ./enc/libcxxrttest-${name}_enc > ${name}_output.log 2>&1 &&
            diff ${name}_output.log ${RESULTDIR}/exp_${name}_output.log")
    endif()
endforeach(testcase)
