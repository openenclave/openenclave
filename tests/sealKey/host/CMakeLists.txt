# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include (oeedl_file)

oeedl_file(../sealKey.edl host gen)

add_executable(sealKey_host host.cpp ${gen})

target_compile_options(sealKey_host PRIVATE
    -Wconversion
    -Wpointer-arith
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++14>
    )

target_include_directories(sealKey_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                           ${CMAKE_CURRENT_SOURCE_DIR})
  
target_link_libraries(sealKey_host oehostapp)
