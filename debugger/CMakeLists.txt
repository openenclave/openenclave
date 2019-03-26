# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(ptraceLib)
add_subdirectory(pythonExtension)

# Copy oe-gdb to build/output/bin so that it can be used
# for debugging enclaves built as part of OE SDK.
file(COPY oegdb DESTINATION ${OE_BINDIR})

install(PROGRAMS oegdb DESTINATION ${CMAKE_INSTALL_BINDIR})
