# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(VectorExceptionEnc sign.conf private.pem
    enc.c
    sigill_handling.c
    )
