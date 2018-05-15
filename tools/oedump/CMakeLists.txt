# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oedump main.c)

target_link_libraries(oedump oehost)

# assemble into proper collector dir
set_property(TARGET oedump PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# test-case
add_test(NAME tools/oedump
    COMMAND oedump $<TARGET_FILE:echo_enc>.signed.so)

# install rule
install (TARGETS oedump DESTINATION ${CMAKE_INSTALL_BINDIR})
