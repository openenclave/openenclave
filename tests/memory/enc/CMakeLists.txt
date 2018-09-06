# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(memory_enc
    basic.c
    enc.c
    stress.c)

target_link_libraries(memory_enc oeenclave)
