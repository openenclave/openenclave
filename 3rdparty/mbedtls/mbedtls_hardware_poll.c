// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/entropy.h>

/*
 * MBEDTLS links this function definition when MBEDTLS_ENTROPY_HARDWARE_ALT
 * is defined in the MBEDTLS config.h file. This is the sole source of entropy
 * for MBEDTLS. All other MBEDTLS entropy sources are disabled since they don't
 * work within enclaves.
 */
int mbedtls_hardware_poll(
    void* data,
    unsigned char* output,
    size_t len,
    size_t* olen)
{
    int ret = -1;
    OE_UNUSED(data);

    if (oe_get_entropy(output, len) != OE_OK)
        goto done;

    if (olen)
        *olen = len;

    ret = 0;

done:
    return ret;
}
