add_library(oehost STATIC
	aesm.c
	calls.c
	create.c
	elf.c
	enclave.c
	error.c
	files.c
	hexdump.c
	load.c
	ocalls.c
	quote.c
	registers.c
	result.c
	sgxdriver.c
	sgxmeasure.c
	sgxtypes.c
	sha.c
	spinlock.c
	tests.c
	thread.c
	typeinfo.c
	aep.S
	enter.S
	entersim.S
	)

target_link_libraries(oehost oe_includes)

target_compile_options(oehost PRIVATE 
	-Wall -Werror -Wno-attributes -Wmissing-prototypes
	-m64 -g -O2
	)
# -fPIC

target_compile_definitions(oehost PRIVATE -DOE_BUILD_UNTRUSTED)

set_property(TARGET oehost PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/host)
install (TARGETS oehost ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/host)
