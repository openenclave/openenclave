# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(VectorException_enc
    enc.c
    sigill_handling.c
    init.cpp
    )

target_link_libraries(VectorException_enc oeenclave)
