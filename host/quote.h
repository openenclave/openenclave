// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_QUOTE_H
#define _OE_HOST_QUOTE_H

#include <openenclave/bits/sgxtypes.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** SGX_GetQuoteSize()
**
**==============================================================================
*/

oe_result_t SGX_GetQuoteSize(uint32_t* quoteSize);

/*
**==============================================================================
**
** SGX_GetQETargetInfo()
**
**==============================================================================
*/

oe_result_t SGX_GetQETargetInfo(SGX_TargetInfo* targetInfo);

/*
**==============================================================================
**
** SGX_GetQuote()
**
**==============================================================================
*/
oe_result_t SGX_GetQuote(
    const SGX_Report* sgxReport,
    uint8_t* quote,
    uint32_t* quoteSize);

OE_EXTERNC_END

#endif /* _OE_HOST_QUOTE_H */
