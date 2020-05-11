// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// This file provides an implementation of EEID attester and verifier plugins.

#ifndef _OE_EEID_ATTESTER_H
#define _OE_EEID_ATTESTER_H

#include <openenclave/internal/sgx/eeid_plugin.h>

OE_EXTERNC_BEGIN

/**
 * Helper function that returns the EEID attester that can then be sent to
 * `oe_register_attester`.
 *
 * @experimental
 *
 * @retval A pointer to the SGEEID attester. This function never fails.
 */
oe_attester_t* oe_eeid_plugin_attester(void);

OE_EXTERNC_END

#endif // _OE_EEID_ATTESTER_H
