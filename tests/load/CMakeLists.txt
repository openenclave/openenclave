add_executable(load main.cpp)

target_link_libraries(load oehost)

target_compile_options(echohost PRIVATE
	-Wall -Werror -g -O2
	)
