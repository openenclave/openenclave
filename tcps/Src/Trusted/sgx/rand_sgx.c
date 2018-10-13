/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <sgx_trts.h>

int Tcps_FillRandom(void* ptr, size_t len)
{
    return sgx_read_rand(ptr, len);
}
