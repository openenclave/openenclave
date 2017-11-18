add_executable(printhost host.cpp)

target_link_libraries(printhost oehost)

target_compile_options(printhost PRIVATE
	-Wall -Werror
	-Wno-error=unused-but-set-variable
	)
target_link_libraries(printhost -rdynamic)
