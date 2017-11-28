add_executable(aesm main.cpp)
target_link_libraries(aesm oehost)
add_test(NAME tests/aesm COMMAND ./aesm)
