# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(no_debug_enc no-debug.conf private.pem enc.cpp)
target_link_libraries(no_debug_enc oecore)
