// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file quote.h
 *
 * This file defines the programming interface verifying quotes for remote
 * attestation.
 *
 */
#ifndef _OE_QUOTE_H
#define _OE_QUOTE_H

#ifdef _OE_ENCLAVE_H
#error "enclave.h must not be in the same compilation unit as quote.h"
#endif

#include "bits/defs.h"
#include "bits/report.h"
#include "bits/result.h"

OE_EXTERNC_BEGIN

/**
 * Verify the integrity of the remote report and its signature.
 *
 * This function verifies that the report signature is valid. It
 * verifies that the signing authority is rooted to a trusted authority
 * such as the enclave platform manufacturer.
 *
 * @param report The buffer containing the report to verify.
 * @param report_size The size of the **report** buffer.
 * @param parsed_report Optional **oe_report_t** structure to populate
 * with the report properties in a standard format.
 *
 * @retval OE_OK The report was successfully created.
 * @retval OE_INVALID_PARAMETER At least one parameter is invalid.
 *
 */
oe_result_t oe_verify_remote_report(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

OE_EXTERNC_END

#endif
