add_executable(aesm main.cpp)

target_link_libraries(aesm oehost)

target_compile_options(aesm PRIVATE -Wall -Werror)

add_test(NAME tests/aesm COMMAND ./aesm)
