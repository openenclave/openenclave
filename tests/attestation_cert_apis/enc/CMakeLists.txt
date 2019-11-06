# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tls.edl enclave gen)

add_enclave(TARGET tls_enc UUID 6cc330ff-c8cf-49d4-92ef-e1674794f820 SOURCES enc.cpp ${gen})

target_include_directories(tls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tls_enc oeenclave oelibc)
