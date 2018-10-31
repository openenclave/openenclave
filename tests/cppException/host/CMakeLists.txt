# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(cppException_host host.cpp)
target_link_libraries(cppException_host oehostapp)
target_compile_options(cppException_host PRIVATE -Wconversion -Wpointer-arith)
