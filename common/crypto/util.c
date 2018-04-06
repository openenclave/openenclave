// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "util.h"
#include <string.h>

/* Verify that the only null terminator is the final byte */
OE_Result OE_CheckForNullTerminator(const void* pemData, size_t pemSize)
{
    OE_Result result = OE_UNEXPECTED;

    /* Check parameters */
    if (!pemData || !pemSize)
    {
        result = OE_UNEXPECTED;
        goto done;
    }

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}
