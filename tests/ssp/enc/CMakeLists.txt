# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../ssp.edl enclave gen)

add_enclave(TARGET ssp_enc UUID f39f25d8-266d-47ad-b9d3-77fb62100d14 SOURCES enc.cpp ${gen})

set_source_files_properties(
  enc.cpp
  PROPERTIES
  COMPILE_FLAGS -fstack-protector-all)

target_include_directories(ssp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ssp_enc oelibcxx)
