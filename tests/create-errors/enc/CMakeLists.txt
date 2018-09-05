# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(create_errors_enc enc.c)
target_link_libraries(create_errors_enc oeenclave)
