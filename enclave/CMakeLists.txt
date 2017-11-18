add_library(oeenclave STATIC
	assert.c
	atexit.c
	calls.c
	globals.c
	hostcalls.c
	hoststack.c
	init.c
	jump.c
	memory.c
	once.c
	report.c
	sbrk.c
	snprintf.c
	spinlock.c
	string.c
	td.c
	thread.c
	abort.S
	exit.S
	main.S
	)

target_link_libraries(oeenclave oe_includes)

target_compile_options(oeenclave PRIVATE 
	-Wall -Werror -Wno-attributes -Wmissing-prototypes -Wstrict-prototypes
	-m64 -g -O2 -fPIC
	-fno-stack-protector -fvisibility=hidden
	)

target_compile_definitions(oeenclave PRIVATE -DOE_BUILD_ENCLAVE)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oeenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
