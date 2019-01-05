# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_library(enclib2 enclib2.c)

target_link_libraries(enclib2 oeenclave)
target_link_options(enclib2 INTERFACE -Wl,--require-defined=enclib2)
