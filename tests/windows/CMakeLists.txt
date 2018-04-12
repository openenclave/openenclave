# Use an external project to place the binaries that you need to copy
# from Linux to their target windows build folders.

Message("WINDOWS CMAKELISTS : inside file.")

if(ADD_WINDOWS_ENCLAVE_TESTS)
include (ExternalProject)
ExternalProject_Add(linux_binaries_include
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_COMMAND} -E copy_directory ${LINUX_BIN_DIR}/ ${VS_CMAKE_TESTS_DIR}/linux
		COMMAND ${CMAKE_COMMAND} -E copy_directory ${WND_BIN_DIR}/ ${VS_CMAKE_TESTS_DIR}/win
		INSTALL_COMMAND ""
    )
	
add_test(tests/echo ${VS_CMAKE_TESTS_DIR}/win/echo/host/echohost ${VS_CMAKE_TESTS_DIR}/linux/echo/enc/echoenc.signed.so)
add_test(tests/ecall ${VS_CMAKE_TESTS_DIR}/win/ecall/host/ecallhost ${VS_CMAKE_TESTS_DIR}/linux/ecall/enc/ecallenc.signed.so)

#add_test(tests/echo host/echohost ./enc/echoenc.signed.so)
	
Message("WINDOWS CMAKELISTS : after command exection.")
endif()