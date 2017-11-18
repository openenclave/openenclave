include(oeidl_file)
oeidl_file(../pingpong.idl host gen)

add_executable(pingponghost host.cpp ${gen})

target_include_directories(pingponghost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingponghost oehost)
target_compile_options(pingponghost PRIVATE -Wall -Werror)
target_link_libraries(pingponghost -rdynamic)
