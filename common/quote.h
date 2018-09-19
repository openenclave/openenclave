// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QUOTE_H
#define _OE_COMMON_QUOTE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t VerifyQuoteImpl(
    const uint8_t* encQuote,
    size_t quoteSize,
    const uint8_t* encPemPckCertificate,
    size_t pemPckCertificateSize,
    const uint8_t* encPckCrl,
    size_t encPckCrlSize,
    const uint8_t* encTcbInfoJson,
    size_t encTcbInfoJsonSize);

OE_EXTERNC_END

#endif // _OE_COMMON_QUOTE_H
