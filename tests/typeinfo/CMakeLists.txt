include(oeidl_file)
oeidl_file(typeinfo.idl host idlfiles)

add_executable(typeinfo
	main.cpp
	${idlfiles}
	)

target_include_directories(typeinfo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(typeinfo PRIVATE -Wall -Werror)
target_link_libraries(typeinfo oehost)

add_test(tests/typeinfo typeinfo)
