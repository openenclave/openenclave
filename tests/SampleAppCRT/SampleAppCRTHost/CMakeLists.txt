# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(SampleAppCRTHost SampleAppCRTHost.cpp)
target_link_libraries(SampleAppCRTHost oehostapp)
target_compile_options(SampleAppCRTHost PRIVATE -Wconversion -Wpointer-arith)
