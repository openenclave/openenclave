include(oeidl_file)
oeidl_file(../tester.idl host gen)

add_executable(testerhost host.cpp ${gen})

target_include_directories(testerhost PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(testerhost oehost)
target_compile_options(testerhost PRIVATE -Wall -Werror)
target_link_libraries(testerhost -rdynamic)
