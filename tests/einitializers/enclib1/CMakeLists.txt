# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_library(enclib1 STATIC enclib1.c)
target_link_libraries(enclib1 oeenclave)
target_link_options(enclib1 INTERFACE -Wl,--require-defined=enclib1)
