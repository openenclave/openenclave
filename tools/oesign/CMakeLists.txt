# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oesign main.c)

target_link_libraries(oesign oehost)
target_compile_options(oesign PRIVATE
    -Wconversion
    -Wpointer-arith
    )


# assemble into proper collector dir
set_property(TARGET oesign PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install (TARGETS oesign EXPORT openenclave DESTINATION ${CMAKE_INSTALL_BINDIR})
