add_executable(stdchost host.cpp)

target_link_libraries(stdchost oehost)

target_compile_options(stdchost PRIVATE
	-Wno-error=unused-but-set-variable
	-Wall -Werror
	)
target_link_libraries(stdchost -rdynamic)
