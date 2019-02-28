# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oesign main.c oedump.c)

target_link_libraries(oesign oehost)

# assemble into proper collector dir
set_property(TARGET oesign PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS oesign EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
