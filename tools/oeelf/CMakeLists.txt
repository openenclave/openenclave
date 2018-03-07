# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oeelf main.c)

target_link_libraries(oeelf oehost)

# assemble into proper collector dir
set_property(TARGET oeelf PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# no install rule - not distributed
install (TARGETS oeelf DESTINATION ${CMAKE_INSTALL_BINDIR})

add_test(oeelf ${OE_BINDIR}/oeelf ${PROJECT_BINARY_DIR}/tests/echo/enc/echoenc.signed.so)

