// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_QUOTE_H
#define _OE_HOST_QUOTE_H

#include <openenclave/internal/sgxtypes.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** sgx_get_quote_size()
**
**==============================================================================
*/

oe_result_t sgx_get_quote_size(size_t* quoteSize);

/*
**==============================================================================
**
** sgx_get_qetarget_info()
**
**==============================================================================
*/

oe_result_t sgx_get_qetarget_info(sgx_target_info_t* targetInfo);

/*
**==============================================================================
**
** sgx_get_quote()
**
**==============================================================================
*/
oe_result_t sgx_get_quote(
    const sgx_report_t* sgxReport,
    uint8_t* quote,
    size_t* quoteSize);

OE_EXTERNC_END

#endif /* _OE_HOST_QUOTE_H */
