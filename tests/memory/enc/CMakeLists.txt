# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(memory_enc
    basic.c
    boundaries.c
    enc.c
    globals.c
    stress.c)

target_link_libraries(memory_enc oeenclave)
