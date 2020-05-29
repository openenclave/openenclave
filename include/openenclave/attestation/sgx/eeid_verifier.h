// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_VERIFIER_H
#define _OE_EEID_VERIFIER_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

#define OE_CLAIM_EEID_BASE_ID "eeid_base_unique_id"

/**
 * oe_sgx_eeid_verifier_initialize
 *
 * Initializes the SGX EEID verifier environment configured for the platform and
 * the calling application.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_sgx_eeid_verifier_initialize(void);

/**
 * oe_sgx_eeid_verifier_shutdown
 *
 * Shuts down the SGX EEID verifier environment configured for the platform and
 * the calling application.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_sgx_eeid_verifier_shutdown(void);

OE_EXTERNC_END

#endif // _OE_EEID_VERIFIER_H
