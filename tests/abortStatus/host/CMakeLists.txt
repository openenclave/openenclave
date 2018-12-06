# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../abortStatus.edl host gen)

add_executable(abortStatus_host host.cpp ${gen})

if(USE_DEBUG_MALLOC)
    target_compile_definitions(abortStatus_host PRIVATE OE_USE_DEBUG_MALLOC)
endif()

target_include_directories(abortStatus_host PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(abortStatus_host oehostapp)
