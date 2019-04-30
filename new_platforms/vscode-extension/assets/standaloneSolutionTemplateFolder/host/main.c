// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdio.h>

#include <openenclave/host.h>

oe_result_t open_enclave();
oe_result_t close_enclave();
oe_result_t call_enclave();

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_OK;
    result = open_enclave();
    if (result != OE_OK)
    {
        return result;
    }
    iothub_module();
    result = close_enclave();
    return result;
}
