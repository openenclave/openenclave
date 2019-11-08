// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file attester.h
 *
 * This file defines the API for getting the SGX attester.
 *
 */

#ifndef _OE_ATTESTATION_SGX_ATTESTER_H
#define _OE_ATTESTATION_SGX_ATTESTER_H

#ifdef _OE_HOST_H
#error "The sgx attester (sgx/attester.h) is only available for the enclave."
#endif

#include <openenclave/attestation/plugin.h>

OE_EXTERNC_BEGIN

/**
 *  The `opt_params` field for `oe_get_evidence` identical to the `opt_params`
 *  field `oe_get_report`. In other words, it is the output of
 * `oe_get_target_info` for local attestation and is ignored for remote
 *  attestation.
 */
typedef void* oe_sgx_plugin_opt_params;

/**
 * Helper function that returns the SGX attester that can then be sent to
 * `oe_register_attester`.
 *
 * @retval A pointer to the SGX attester. This function never fails.
 */
oe_attester_t* oe_sgx_plugin_attester(void);

OE_EXTERNC_END

#endif /* _OE_ATTESTATION_SGX_ATTESTER_H */