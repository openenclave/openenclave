// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_QUOTE_H
#define _OE_COMMON_QUOTE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t VerifyQuoteImpl(
    const uint8_t* enc_quote,
    size_t quote_size,
    const uint8_t* enc_pem_pck_certificate,
    size_t pem_pck_certificate_size,
    const uint8_t* enc_pck_crl,
    size_t enc_pck_crl_size,
    const uint8_t* enc_tcb_info_json,
    size_t enc_tcb_info_json_size);

OE_EXTERNC_END

#endif // _OE_COMMON_QUOTE_H
