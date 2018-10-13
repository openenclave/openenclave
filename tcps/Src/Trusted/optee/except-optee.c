/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <sgx_trts_exception.h>

void* sgx_register_exception_handler(
    int is_first_handler, 
    sgx_exception_handler_t exception_handler)
{
    return exception_handler;
}

int sgx_unregister_exception_handler(void *handler)
{
    return 1;
}