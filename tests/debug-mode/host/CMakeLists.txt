# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(debug_host host.c)


if(USE_LIBSGX)
    target_compile_definitions(debug_host PRIVATE OE_USE_LIBSGX)
endif()

target_link_libraries(debug_host oehostapp)
