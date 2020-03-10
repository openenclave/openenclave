# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../plugin.edl)

add_custom_command(
    OUTPUT plugin_t.h plugin_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET plugin_enc UUID 0ed4cfa8-3d98-4ef6-a8e6-b3120517ccac SOURCES enc.c ../plugin/tests.c ${CMAKE_CURRENT_BINARY_DIR}/plugin_t.c)

enclave_include_directories(plugin_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(plugin_enc oeenclave oelibc)
