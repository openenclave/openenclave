add_executable(ocallhost host.cpp)

target_link_libraries(ocallhost oehost)

target_compile_options(ocallhost PRIVATE
	-Wall -Werror
	-Wno-error=unused-but-set-variable -Wno-error=unused-variable
	)
target_link_libraries(ocallhost -rdynamic)
