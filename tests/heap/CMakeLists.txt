add_executable(heap main.c)
target_link_libraries(heap oehost)
add_test(tests/heap heap)

