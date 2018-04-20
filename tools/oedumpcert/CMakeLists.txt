# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oedumpcert main.c)

target_link_libraries(oedumpcert oehost)

# assemble into proper collector dir
set_property(TARGET oedumpcert PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# test-cases
add_test(NAME tests/oedumpcert.1 COMMAND oedumpcert cert.pem WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME tests/oedumpcert.2 COMMAND oedumpcert chain.pem WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# install rule
install (TARGETS oedumpcert DESTINATION ${CMAKE_INSTALL_BINDIR})

