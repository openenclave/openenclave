add_executable(libcxxhost host.cpp)

target_link_libraries(libcxxhost oehost)
target_compile_options(libcxxhost PRIVATE -Wall -Werror)
target_link_libraries(libcxxhost -rdynamic)
