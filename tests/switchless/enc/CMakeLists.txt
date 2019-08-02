# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#add_custom_command(
#    OUTPUT switchless_t.h switchless_t.c switchless_args.h
#    DEPENDS edger8r ../switchless.edl
#    COMMAND edger8r --experimental --trusted
#    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/.. switchless.edl)

add_enclave(TARGET switchless_enc SOURCES enc.c switchless_t.c)

#target_include_directories(switchless_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_enc oelibc)
