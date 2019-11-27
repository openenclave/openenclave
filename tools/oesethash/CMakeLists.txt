# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oesethash main.c)

target_link_libraries(oesethash oehost)

# assemble into proper collector dir
set_property(TARGET oesethash PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install(TARGETS oesethash EXPORT openenclave-targets DESTINATION ${CMAKE_INSTALL_BINDIR})
