add_executable(ricochethost host.c)

target_link_libraries(ricochethost oehost)

target_compile_options(ricochethost PRIVATE
	-Wall -Werror
	-Wno-error=unused-variable
	)
target_link_libraries(ricochethost -rdynamic)
