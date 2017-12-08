add_library(eal_host STATIC
	eal_host.c
    )

# we and dependents need the OE includes to compile
target_link_libraries(eal_host oe_includes)

find_library(DL_LIB NAMES dl)
find_package(Threads REQUIRED)

# linking also requires a number of libs on the eal_host
target_link_libraries(eal_host  ${DL_LIB} Threads::Threads)

target_compile_options(eal_host PRIVATE 
    -Wall -Werror -Wno-attributes -Wmissing-prototypes
    -m64 -fPIC
    )
target_compile_definitions(eal_host PRIVATE -DOE_BUILD_UNTRUSTED)

# assemble lib-archive into proper dir
set_property(TARGET eal_host PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/eal_host)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")

# install lib-archive upon install-time
install (TARGETS eal_host ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/eal_host)