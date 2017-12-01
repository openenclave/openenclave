include(oeidl_file)
include(add_enclave_executable)

oeidl_file(../file.idl enclave gen)
add_enclave_executable(fileenc sign.conf private.pem
    enc.cpp
    ${gen}
    )

target_include_directories(fileenc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(fileenc oeidl oelibc)
