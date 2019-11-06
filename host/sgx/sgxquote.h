// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXQUOTE_H
#define _OE_SGXQUOTE_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

#define OE_MAX_UINT32 0xFFFFFFFF

oe_result_t oe_sgx_qe_get_target_info(uint8_t* target_info);
oe_result_t oe_sgx_qe_get_quote_size(size_t* quote_size);
oe_result_t oe_sgx_qe_get_quote(
    uint8_t* report,
    size_t quote_size,
    uint8_t* quote);

#endif // _OE_SGXQUOTE_H
