# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(dox2md
    element.cpp
    err.cpp
    main.cpp
    )

target_link_libraries(dox2md expat)

# assemble into proper collector dir
set_property(TARGET dox2md PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# no install rule - not distributed
