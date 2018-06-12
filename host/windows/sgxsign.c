// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/result.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/sha.h>

oe_result_t oe_sgx_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t productID,
    uint16_t securityVersion,
    const char* pemData,
    size_t pemSize,
    sgx_sigstruct_t* sigstruct)
{
    /* ATTN: unsupported on Windows */
    return OE_UNSUPPORTED;
}
