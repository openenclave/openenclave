// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>

OE_ECALL void EnclaveEcho(void* args)
{
    oe_call_host("HostEcho", args);
}
