// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_ATTESTER_H
#define _OE_EEID_ATTESTER_H

#ifndef OE_BUILD_ENCLAVE
#error \
    "The sgx attester (sgx/eeid_attester.h) is only available for the enclave."
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/**
 * oe_sgx_eeid_attester_initialize
 *
 * Initializes the SGX EEID attester environment configured for the platform and
 * the calling application.
 * This function is only available in the enclave.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_sgx_eeid_attester_initialize(void);

/**
 * oe_sgx_eeid_attester_shutdown
 *
 * Shuts down the SGX EEID attester environment configured for the platform and
 * the calling application.
 * This function is only available in the enclave.
 *
 * This function is idempotent and can be called multiple times without
 * adverse effect.
 *
 * @experimental
 *
 * @retval OE_OK on success.
 * @retval other appropriate error code.
 */
oe_result_t oe_sgx_eeid_attester_shutdown(void);

OE_EXTERNC_END

#endif // _OE_EEID_ATTESTER_H
