add_executable(mbedhost host.c)

target_link_libraries(mbedhost oehost)

target_compile_options(mbedhost PRIVATE
	-Wall -Werror -Wall
	-Werror -Wno-error=unused-variable
	)
target_link_libraries(mbedhost -rdynamic)
