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

OE_EXTERNC_BEGIN

/**
 * Helper function that returns the SGX verifier that can then be sent to
 * `oe_register_verifier`.
 *
 * @retval A pointer to the SGX verifier. This function never fails.
 */
oe_verifier_t* oe_sgx_plugin_verifier(void);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */
