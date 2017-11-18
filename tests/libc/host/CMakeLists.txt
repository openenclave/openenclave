add_executable(libchost host.cpp)

target_link_libraries(libchost oehost)

target_compile_options(libchost PRIVATE -Wall -Werror)
target_link_libraries(libchost -rdynamic)
