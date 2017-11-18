add_executable(ecallhost host.cpp)

target_link_libraries(ecallhost oehost)

target_compile_options(ecallhost PRIVATE
	-Wall -Werror
	-Wno-error=unused-but-set-variable
	)
target_link_libraries(ecallhost -rdynamic)
