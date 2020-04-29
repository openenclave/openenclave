# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


## This function is to add test for given host file and enclave file.
## TEST_NAME    : test name for add test.
## HOST_FILE    : Host application executable file name.
## ENC_FILE     : Signed/Unsigned enclave file name.
## DESCRIPTION  : For ADD_WINDOWS_ENCLAVE_TESTS enabled function will copy signed
##                      enclave file from Linux build location to windows build location
##                      after checking if both host and enclave file exists at specified
##                      location.
##                      NOTE : Any additional arguments after ENC_FILE argument are passed
##                      directly to add_test.

function(add_enclave_test TEST_NAME HOST_FILE ENC_FILE)

    if (ADD_WINDOWS_ENCLAVE_TESTS)

        # Get the test directory name only. This assumes that all tests invoking this
        # function are nested under tests/ in the source tree, and is used to construct
        # a corresponding subpath to the linux binaries.
        set(OE_TESTS_PATH_NAME "${PROJECT_SOURCE_DIR}/tests/")
        string(LENGTH ${OE_TESTS_PATH_NAME} OE_TESTS_PATH_NAME_LENGTH)
        string(FIND ${CMAKE_CURRENT_SOURCE_DIR} ${OE_TESTS_PATH_NAME} TEST_DIR_INDEX)

        if (${TEST_DIR_INDEX} GREATER -1)
            math(EXPR TEST_DIR_INDEX "${TEST_DIR_INDEX}+${OE_TESTS_PATH_NAME_LENGTH}")
            string(SUBSTRING ${CMAKE_CURRENT_SOURCE_DIR} ${TEST_DIR_INDEX} -1 TEST_DIR)
        endif()

        if (${TEST_DIR_INDEX} LESS_EQUAL -1 OR TEST_DIR STREQUAL "")
            message(FATAL_ERROR "add_enclave_test can only be used in a subfolder of ${OE_TESTS_PATH_NAME} with ADD_WINDOWS_ENCLAVE_TESTS.")
        endif()

        # (HACK1) Ideally, the path to the enclave should be $<TARGET_FILE:${ENC_FILE}>
        # However, for windows, the Linux build of the enclave is used for testing.
        # Instead of passing in "enc" as the subpath, we are using "enc" as the default
        # enclave subpath and "host" as the default host subpath.
        # This hack can be removed when CMake on Windows produces ELF enclaves.
        set(TEST_ENCSUBPATH enc)

        # (HACK2) This is a hack to figure out the target name for the linux enclave
        # Ideally, the name of the enclave is found by $<TARGET_FILE:${ENC_FILE}>
        # However, on windows, testing is done with the Linux build of the enclave.
        # This hack can be removed when CMake on Windows produces ELF enclaves.
        set(TEST_ENCFILE ${ENC_FILE})
        if(ENC_FILE MATCHES ".*_signed")
            string(REGEX REPLACE "_signed" ".signed" TEST_ENCFILE ${ENC_FILE})
        endif()

        # Copy the enclave subfolder from Linux
        # This takes a dependency on host binary to make sure it exists, in addition to
        # enclave binary in linux. It should only be executed once for the target build
        # directory so that multiple tests hosted in the same enclave folder are copied
        # only once.
        if (NOT TARGET ${CMAKE_CURRENT_BINARY_DIR}__windows_include)
            add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}_windows_include
                COMMAND ${CMAKE_COMMAND} -E copy_directory ${LINUX_BIN_DIR}/${TEST_DIR}/${TEST_ENCSUBPATH} ${CMAKE_CURRENT_BINARY_DIR}/${TEST_ENCSUBPATH}
                DEPENDS $<TARGET_FILE:${HOST_FILE}> ${LINUX_BIN_DIR}/${TEST_DIR}/${TEST_ENCSUBPATH}/${TEST_ENCFILE}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                )
        endif()

        # Add a custom target to ALL so that this step always needs to be run if
        # this function is invoked
        get_filename_component(TEST_NAME_WITHOUT_SLASH ${TEST_NAME} NAME)
        add_custom_target(${TEST_NAME_WITHOUT_SLASH}.windows ALL
            DEPENDS ${CMAKE_CURRENT_BINARY_DIR}_windows_include
            )

        add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${HOST_FILE}> ${CMAKE_CURRENT_BINARY_DIR}/${TEST_ENCSUBPATH}/${TEST_ENCFILE} ${ARGN})

        if (LVI_MITIGATION MATCHES ControlFlow AND NOT LVI_MITIGATION_SKIP_TESTS)
            set(TEST_NAME_LVI "${TEST_NAME}-lvi-cfg")
            set(TEST_ENCFILE_LVI ${TEST_ENCFILE})
            if (TEST_ENCFILE_LVI MATCHES ".*\.signed")
                string(REPLACE ".signed" "-lvi-cfg.signed" TEST_ENCFILE_LVI "${TEST_ENCFILE_LVI}")
            else()
                string(CONCAT TEST_ENCFILE_LVI "${TEST_ENCFILE_LVI}" "-lvi-cfg")
            endif()
            add_test(NAME ${TEST_NAME_LVI} COMMAND $<TARGET_FILE:${HOST_FILE}> ${CMAKE_CURRENT_BINARY_DIR}/${TEST_ENCSUBPATH}/${TEST_ENCFILE_LVI} ${ARGN})
        endif()

    elseif (UNIX OR USE_CLANGW)
        add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${HOST_FILE}> $<TARGET_FILE:${ENC_FILE}> ${ARGN})
        if (LVI_MITIGATION MATCHES ControlFlow AND NOT LVI_MITIGATION_SKIP_TESTS)
            set(TEST_NAME_LVI "${TEST_NAME}-lvi-cfg")
            set(ENC_FILE_LVI ${ENC_FILE}-lvi-cfg)
            if (ENC_FILE MATCHES ".*_signed$")
                string(REPLACE "_signed" "-lvi-cfg_signed" ENC_FILE_LVI "${ENC_FILE}")
            endif()
            add_test(NAME ${TEST_NAME_LVI} COMMAND $<TARGET_FILE:${HOST_FILE}> $<TARGET_FILE:${ENC_FILE_LVI}> ${ARGN})
        endif()
    endif()

endfunction(add_enclave_test)
