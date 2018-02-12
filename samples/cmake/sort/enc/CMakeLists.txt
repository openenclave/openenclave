include(add_enclave_executable)
add_enclave_executable(samples-sortenc sort.conf private.pem
    enc.cpp
    )
target_link_libraries(samples-sortenc oelibcxx)
