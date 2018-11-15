# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../safecrt.edl enclave gen)

add_executable(safecrt_enc
    ../common/test.cpp
    enc.cpp
    ${gen}
)

target_include_directories(safecrt_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(safecrt_enc oelibcxx oeenclave)
