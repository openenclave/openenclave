// Copyright (c) Open Enclave SDK contributors.
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

oe_result_t sgx_get_quote_size(size_t* quote_size);

/*
**==============================================================================
**
** sgx_get_qetarget_info()
**
**==============================================================================
*/

oe_result_t sgx_get_qetarget_info(sgx_target_info_t* target_info);

/*
**==============================================================================
**
** sgx_get_quote()
**
**==============================================================================
*/
oe_result_t sgx_get_quote(
    const sgx_report_t* sgx_report,
    uint8_t* quote,
    size_t* quote_size);

OE_EXTERNC_END

#endif /* _OE_HOST_QUOTE_H */
