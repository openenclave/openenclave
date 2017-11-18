add_executable(threadhost host.cpp)

target_link_libraries(threadhost oehost)

target_compile_options(threadhost PRIVATE
	-Wno-error=unused-variable
	-Wall -Werror
	)
target_link_libraries(threadhost -rdynamic)
