# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../tests.edl enclave gen)
add_executable(report_enc enc.cpp datetime.cpp ${gen})

target_include_directories(report_enc PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(report_enc oeenclave)
