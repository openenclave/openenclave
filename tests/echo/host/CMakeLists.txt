add_executable(echohost	host.c)

target_link_libraries(echohost oehost)

target_compile_options(echohost PRIVATE -Wall -Werror)
target_link_libraries(echohost -rdynamic)
