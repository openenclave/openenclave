# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(VectorException_host host.c)
target_link_libraries(VectorException_host oehostapp)
target_compile_options(VectorException_host PRIVATE -Wconversion -Wpointer-arith)
