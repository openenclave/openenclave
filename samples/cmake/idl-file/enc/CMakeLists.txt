include(oeidl_file)
include(add_enclave_executable)

oeidl_file(../file.idl enclave gen)
add_enclave_executable(samples-fileenc sign.conf private.pem
    enc.cpp
    ${gen}
    )

target_include_directories(samples-fileenc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(samples-fileenc oeidl oelibc)
