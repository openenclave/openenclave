# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../create_rapid.edl enclave gen)

# TODO: Does this need CXX?
add_enclave(TARGET create_rapid_enc UUID 688ab13f-5bc0-40af-8dc6-01d007fd2210 SOURCES enc.cpp ${gen})

target_include_directories(create_rapid_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_rapid_enc oelibc)
