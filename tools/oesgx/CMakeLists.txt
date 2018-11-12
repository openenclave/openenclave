# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(oesgx oesgx.c)

target_link_libraries(oesgx oehost)

if (UNIX)
    target_compile_options(oesgx PRIVATE
    -Wconversion
    -Wpointer-arith
    )
endif()

# assemble into proper collector dir
set_property(TARGET oesgx PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install (TARGETS oesgx DESTINATION ${CMAKE_INSTALL_BINDIR})

