# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(initializers_enc enc.c)

target_link_libraries(initializers_enc oeenclave)
