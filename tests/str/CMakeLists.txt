add_executable(str main.c)

target_link_libraries(str oehost)

target_compile_options(str PRIVATE
	-Wall -Werror
	-Wno-error=unused-variable
	-Wno-error=unused-but-set-variable
	)

add_test(NAME tests/str COMMAND str WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
