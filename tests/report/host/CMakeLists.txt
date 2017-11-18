add_executable(reporthost host.cpp)

target_link_libraries(reporthost oehost)

target_compile_options(reporthost PRIVATE -Wall -Werror)
target_link_libraries(reporthost -rdynamic)
