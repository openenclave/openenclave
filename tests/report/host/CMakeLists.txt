# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(report_host host.cpp)

if(USE_AESM)
    target_compile_definitions(report_host PRIVATE OE_USE_AESM)
endif()

target_link_libraries(report_host oehostapp)
