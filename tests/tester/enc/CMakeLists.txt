include(oeidl_file)
include(add_enclave_executable)

oeidl_file(../tester.idl enclave gen)
add_enclave_executable(testerenc sign.conf private.pem
    enc.cpp
    ${gen}
    )

target_include_directories(testerenc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(testerenc oeidl oelibc)
