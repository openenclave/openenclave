add_executable(stdcxxhost host.cpp)

target_link_libraries(stdcxxhost oehost)

target_compile_options(stdcxxhost PRIVATE
	-Wno-error=unused-but-set-variable
	-Wall -Werror
	)
target_link_libraries(stdcxxhost -rdynamic)
