# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(report_enc sign.conf private.pem
    enc.cpp
    )

if(USE_LIBSGX)
    target_compile_definitions(report_enc PRIVATE OE_USE_LIBSGX)
endif()    

target_link_libraries(report_enc oelibc oeenclave)
