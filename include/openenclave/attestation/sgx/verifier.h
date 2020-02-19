// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file verifier.h
 *
 * This file defines the API for getting the SGX verifier.
 *
 */

#ifndef _OE_ATTESTATION_SGX_VERIFIER_H
#define _OE_ATTESTATION_SGX_VERIFIER_H

#include <openenclave/attestation/plugin.h>

#if (OE_API_VERSION < 3)
#define oe_sgx_plugin_verifier oe_sgx_plugin_ecdsa_p256_verifier
#endif

OE_EXTERNC_BEGIN

/**
 * Helper function that returns the SGX local verifier that can then be
 * sent to `oe_register_verifier`.
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
oe_verifier_t* oe_sgx_plugin_local_verifier(void);

/**
 * Helper function that returns the SGX ECDSA P256 verifier that can then
 * be sent to `oe_register_verifier`.
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
oe_verifier_t* oe_sgx_plugin_ecdsa_p256_verifier(void);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */
