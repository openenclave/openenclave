# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# TODO: Does this need CXX?
add_enclave(TARGET VectorException_enc SOURCES enc.c sigill_handling.c init.cpp)
