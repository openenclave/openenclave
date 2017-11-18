# Build the IDL enclave library

add_library(oeidl STATIC
	typeinfo.c
	)

target_compile_options(oeidl PRIVATE
	-Wall
	-Werror
	-m64
	-nostdinc
	-Wno-attributes
	-fPIC
	-fno-stack-protector
	-fvisibility=hidden
	-Wmissing-prototypes
	-Wstrict-prototypes
	-fno-builtin-memcpy
	-fno-builtin-memset
	-fno-builtin-__vfprintf_chk
	-fno-builtin-__memset_chk
	)

target_compile_definitions(oeidl PRIVATE -DOE_BUILD_ENCLAVE)

# this project (and is dependents) require the enclave headers+lib
target_link_libraries(oeidl oelibc)

# assemble lib-archive into proper dir
set_property(TARGET oeidl PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

# install lib-archive upon install-time
install (TARGETS oeidl ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
