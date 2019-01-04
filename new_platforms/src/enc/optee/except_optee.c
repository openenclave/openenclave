/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "oeshim_enc.h"

#define DUMMY_HANDLE ((void*)0xffffffff)

void* oe_register_exception_handler(void)
{
    /* TODO: need to implement this */
    return DUMMY_HANDLE;
}

int oe_unregister_exception_handler(void* handle)
{
    /* TODO: need to implement this */
    return (handle == DUMMY_HANDLE) ? 1 : 0;
}
