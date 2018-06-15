// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H_
#define _ARGS_H_

#include <openenclave/bits/types.h>

struct VerifyQuoteArgs
{
    uint8_t* quote;     /* in */
    uint32_t quote_size; /* in */

    uint8_t* pem_pck_certificate;     /* in */
    uint32_t pem_pck_certificate_size; /* in */

    uint8_t* pck_crl;     /* in */
    uint32_t pck_crl_size; /* in */

    uint8_t* tcb_info_json;     /* in */
    uint32_t tcb_info_json_size; /* in */

    oe_result_t result; /* out */
};

#endif //_ARGS_H_
