# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../tls.edl enclave gen)

add_executable(tls_enc enc.cpp ${gen})

target_include_directories(tls_enc PRIVATE
                          ${CMAKE_CURRENT_BINARY_DIR}
                          ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(tls_enc oeenclave oelibc)
