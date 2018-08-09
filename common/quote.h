// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QUOTE_H
#define _OE_COMMON_QUOTE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t VerifyQuoteImpl(
    const uint8_t* encQuote,
    uint32_t quoteSize,
    const uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    const uint8_t* encTcbInfoJson,
    uint32_t encTcbInfoJsonSize,
    const oe_utc_date_time_t* minCrlTcbIssueDate);

// 21 characters including null terminator.
#define ISO_861_DATE_LENGTH (21)

/**
 * Validate and convert dateTime to ISO 861 format:
 * YYYY-MM-DDThh:mm:ssZ
 */
oe_result_t convertToISO861(
    const oe_utc_date_time_t* dateTime,
    char* iso861String);

OE_EXTERNC_END

#endif // _OE_COMMON_QUOTE_H
