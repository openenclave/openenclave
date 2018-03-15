// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "util.h"

/* Verify that the only null terminator is the final byte */
OE_Result OE_CheckForNullTerminator(const void* pemData, size_t pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    const char* p = (const char*)pemData;
    const char* end = (const char*)pemData + pemSize;

    /* Check parameters */
    if (!pemData || !pemSize)
        goto done;

    /* Search for a null terminator */
    while (*p && p != end)
        p++;

    /* Check that null terminator must be the last byte */
    if (p != end - 1)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}
