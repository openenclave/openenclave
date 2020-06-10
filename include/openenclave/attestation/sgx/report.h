// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file report.h
 *
 * This file defines helper functions for verifying an SGX report.
 *
 */

#ifndef _OE_ATTESTATION_SGX_REPORT_H
#define _OE_ATTESTATION_SGX_REPORT_H

#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/**
 * Get the signer ID for the specified public key.
 *
 * @param[in] pem The signer's public key in PEM format.
 * @param[in] pem_size Size of **pem** (including the zero-terminator).
 * @param[out] signer_id A buffer that receives the signer ID.
 * @param[in,out] signer_id_size buffer size on input; actual size on output.
 *
 * @retval OE_OK upon success
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 * @return OE_BUFFER_TOO_SMALL buffer is too small and **signer_id_size**
 * contains the required size.
 */
oe_result_t oe_sgx_get_signer_id_from_public_key(
    const char* pem,
    size_t pem_size,
    uint8_t* signer_id,
    size_t* signer_id_size);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_REPORT_H */
