# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oe_ptrace SHARED
    oe_ptrace.c
	inferior_status.c
    enclave_context.c
	)

# we and dependents need the OE includes to compile
target_link_libraries(oe_ptrace oe_includes)

find_library(DL_LIB NAMES dl)
find_package(Threads REQUIRED)

# linking also requires a number of libs on the debugger
target_link_libraries(oe_ptrace ${DL_LIB} Threads::Threads)

target_compile_options(oe_ptrace PRIVATE 
    -Wall -Werror -Wno-attributes -Wmissing-prototypes
    -m64
    )
target_compile_definitions(oe_ptrace PRIVATE -DOE_BUILD_UNTRUSTED -D_GNU_SOURCE)

set_property(TARGET oe_ptrace PROPERTY LIBRARY_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/debugger)

# install lib-archive upon install-time
install (TARGETS oe_ptrace LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger)

