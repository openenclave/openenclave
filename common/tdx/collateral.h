// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TDX_COLLATERAL_H
#define _OE_COMMON_TDX_COLLATERAL_H

#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/report.h>

OE_EXTERNC_BEGIN

oe_result_t oe_get_tdx_quote_verification_collateral(
    const uint8_t* p_quote,
    uint32_t quote_size,
    uint8_t** pp_quote_collateral,
    uint32_t* p_collateral_size);

oe_result_t oe_free_tdx_quote_verification_collateral(
    uint8_t* p_quote_collateral);

OE_EXTERNC_END

#endif // _OE_COMMON_TDX_COLLATERAL_H
