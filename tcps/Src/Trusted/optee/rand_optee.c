/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>
#include <tee_api.h>
#include "tcps_stdlib_t.h"

#include "user_settings.h"

pid_t getpid(void)
{
    return 0x123;
}

/* Required by wolfssl */
int custom_rand_generate_block(unsigned char* output, unsigned int sz)
{
    TEE_GenerateRandom(output, sz);
    return 0;
}

/* Required by wolfssl */
unsigned int custom_rand_generate(void)
{
    unsigned int u;

    TEE_GenerateRandom(&u, sizeof(u));
    return u;
}

sgx_status_t sgx_read_rand(unsigned char *ptr, size_t len)
{
    return Tcps_FillRandom(ptr, len);
}

int Tcps_FillRandom(void* ptr, size_t len)
{
    TEE_GenerateRandom(ptr, len);
    return 0;
}
