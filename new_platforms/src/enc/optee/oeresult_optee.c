/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#ifdef LINUX
#include "sal_unsup.h"
#endif

#include <stddef.h>

#include <openenclave/bits/result.h>
#include <tee_internal_api.h>

oe_result_t get_oe_result_from_tee_result(TEE_Result status)
{
    switch (status)
    {
        case TEE_SUCCESS:
            return OE_OK;
        case TEE_ERROR_SHORT_BUFFER:
            return OE_BUFFER_TOO_SMALL;
        case TEE_ERROR_BAD_PARAMETERS:
            return OE_INVALID_PARAMETER;
        case TEE_ERROR_OUT_OF_MEMORY:
            return OE_OUT_OF_MEMORY;
        case TEE_ERROR_NOT_SUPPORTED:
            return OE_UNSUPPORTED;
        case TEE_ERROR_ITEM_NOT_FOUND:
            return OE_NOT_FOUND;
        case TEE_ERROR_BUSY:
            return OE_BUSY;
        default:
            return OE_FAILURE;
    }
}