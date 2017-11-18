add_executable(mem main.c)

target_link_libraries(mem oehost)

target_compile_options(echohost PRIVATE -Wall -Werror)

add_test(tests/mem mem)

