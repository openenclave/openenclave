// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

OE_ECALL void enclave_helloworld(void* args_)
{
    oe_call_host("host_hello", NULL);
}
