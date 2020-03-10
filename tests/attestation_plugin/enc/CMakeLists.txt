# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../plugin.edl enclave gen)

add_enclave(TARGET plugin_enc UUID 0ed4cfa8-3d98-4ef6-a8e6-b3120517ccac SOURCES enc.c ../plugin/tests.c ${gen})

enclave_include_directories(plugin_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(plugin_enc oeenclave oelibc)
