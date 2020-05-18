# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

find_library(DL_LIB NAMES dl)
add_library(openenclave::dl SHARED IMPORTED)
set_target_properties(openenclave::dl PROPERTIES IMPORTED_LOCATION ${DL_LIB})

find_package(Threads REQUIRED)

add_library(oe_ptrace SHARED oe_ptrace.c inferior_status.c enclave_context.c)

target_link_libraries(oe_ptrace oe_includes openenclave::dl Threads::Threads)

target_compile_options(oe_ptrace PRIVATE -Wall -Werror -Wno-attributes
                                         -Wmissing-prototypes -m64)

target_compile_definitions(oe_ptrace PRIVATE -DOE_BUILD_UNTRUSTED -D_GNU_SOURCE)

set_property(TARGET oe_ptrace PROPERTY LIBRARY_OUTPUT_DIRECTORY
                                       ${OE_LIBDIR}/openenclave/debugger)

install(TARGETS oe_ptrace
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger)
