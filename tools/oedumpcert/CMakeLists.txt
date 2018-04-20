# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oedumpcert main.c)

target_link_libraries(oedumpcert oehost)

# assemble into proper collector dir
set_property(TARGET oedumpcert PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# test-case
add_test(NAME tools/oedump COMMAND oedumpcert cert.pem)

# install rule
install (TARGETS oedumpcert DESTINATION ${CMAKE_INSTALL_BINDIR})
