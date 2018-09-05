# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(report_enc enc.cpp datetime.cpp)

target_compile_options(report_enc PRIVATE
    -std=c++11
)

if(USE_LIBSGX)
    target_compile_definitions(report_enc PRIVATE OE_USE_LIBSGX)
endif()    

target_link_libraries(report_enc oeenclave)
