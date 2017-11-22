add_executable(mem main.c)
target_link_libraries(mem oehost)
add_test(tests/mem mem)

