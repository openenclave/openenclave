add_library(sgx_ptrace SHARED
    oe_ptrace.c
	inferior_status.c
	)

# we and dependents need the OE includes to compile
target_link_libraries(sgx_ptrace oe_includes)
target_link_libraries(sgx_ptrace eal_host)

find_library(DL_LIB NAMES dl)
find_package(Threads REQUIRED)

# linking also requires a number of libs on the debugger
target_link_libraries(sgx_ptrace ${DL_LIB} Threads::Threads)

target_compile_options(sgx_ptrace PRIVATE 
    -Wall -Werror -Wno-attributes -Wmissing-prototypes
    -m64
    )
target_compile_definitions(sgx_ptrace PRIVATE -DOE_BUILD_UNTRUSTED)

# assemble lib-archive into proper dir
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")

# install lib-archive upon install-time
install (TARGETS sgx_ptrace LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger)
