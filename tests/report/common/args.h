// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H_
#define _ARGS_H_

#include <openenclave/bits/types.h>

struct VerifyQuoteArgs
{
    uint8_t* quote;   /* in */
    size_t quote_size; /* in */

    uint8_t* pem_pck_certificate;   /* in */
    size_t pem_pck_certificate_size; /* in */

    uint8_t* pck_crl;   /* in */
    size_t pck_crl_size; /* in */

    uint8_t* tcb_info_json;   /* in */
    size_t tcb_info_json_size; /* in */

    oe_result_t result; /* out */
};

struct VerifyTCBInfoArgs
{
    uint8_t* tcb_info;       /* in */
    size_t tcb_info_size;     /* in */
    void* platform_tcb_level; /* in */
    void* parsed_tcb_info;    /* out */
    oe_result_t result;     /* out */
};

struct ParseJsonArgs
{
    uint8_t* json;      /* in */
    size_t json_size;    /* in */
    oe_result_t result; /* out */
};

#endif //_ARGS_H_
