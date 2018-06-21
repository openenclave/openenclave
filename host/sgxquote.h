// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXQUOTE_H
#define _OE_SGXQUOTE_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

oe_result_t oe_sgx_qe_get_target_info(uint8_t* targetInfo);
oe_result_t oe_sgx_qe_get_quote_size(uint32_t* quoteSize);
oe_result_t oe_sgx_qe_get_quote(
    uint8_t* report,
    uint32_t quoteSize,
    uint8_t* quote);

#endif // _OE_SGXQUOTE_H
