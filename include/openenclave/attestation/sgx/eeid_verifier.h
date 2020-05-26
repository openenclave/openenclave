// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_VERIFIER_H
#define _OE_EEID_VERIFIER_H

#include <openenclave/internal/sgx/eeid_plugin.h>

OE_EXTERNC_BEGIN

#define OE_CLAIM_EEID_BASE_ID "eeid_base_unique_id"

/**
 * Helper function that returns the EEID verifier that can then be sent to
 * `oe_register_verifier`.
 *
 * @experimental
 *
 * @retval A pointer to the EEID verifier. This function never fails.
 */
oe_verifier_t* oe_eeid_plugin_verifier(void);

OE_EXTERNC_END

#endif // _OE_EEID_VERIFIER_H
