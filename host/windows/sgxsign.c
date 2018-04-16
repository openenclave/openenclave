// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/sha.h>
#include <openenclave/result.h>

OE_Result OE_SGXSignEnclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t productID,
    uint16_t securityVersion,
    const char* pemData,
    size_t pemSize,
    SGX_SigStruct* sigstruct)
{
    /* ATTN: unsupported on Windows */
    return OE_UNSUPPORTED;
}
