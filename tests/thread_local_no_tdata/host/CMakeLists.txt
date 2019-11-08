# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.


oeedl_file(../no_tdata.edl host gen)

add_executable(no_tdata_host host.cpp ${gen})

target_include_directories(no_tdata_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(no_tdata_host PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>
    )
target_link_libraries(no_tdata_host oehostapp)
