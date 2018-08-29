// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_REPORT_H_
#define _OE_INCLUDE_REPORT_H_

#include <openenclave/bits/types.h>
#include <openenclave/internal/sgxtypes.h>

/*
**==============================================================================
**
** oe_init_quote_args_t
**
**==============================================================================
*/
typedef struct _oe_init_quote_args
{
    oe_result_t result;
    sgx_target_info_t targetInfo;
    sgx_epid_group_id_t epidGroupID;
} oe_init_quote_args_t;

/*
**==============================================================================
**
** oe_get_qetarget_info_args_t
**
**==============================================================================
*/
typedef struct _oe_get_qetarget_info_args
{
    oe_result_t result;
    sgx_target_info_t targetInfo;
} oe_get_qetarget_info_args_t;

/*
**==============================================================================
**
** _oe_get_quote_args
**
**==============================================================================
*/
typedef struct _oe_get_quote_args
{
    oe_result_t result;
    sgx_report_t sgxReport;
    size_t quoteSize;
    uint8_t quote[1];
} oe_get_quote_args_t;

/*
**==============================================================================
**
** oe_get_report_args_t
**
**==============================================================================
*/
typedef struct _oe_get_report_args
{
    oe_result_t result; /* out */

    uint32_t flags; /* in */

    uint8_t optParams[sizeof(sgx_target_info_t)]; /* in */
    size_t optParamsSize;                         /* in */

    uint8_t* reportBuffer;   /* ptr to output buffer */
    size_t reportBufferSize; /* in-out */
} oe_get_report_args_t;

/*
**==============================================================================
**
** oe_verify_report_args_t
**
**==============================================================================
*/
typedef struct _oe_verify_report_args
{
    oe_result_t result; /* out */

    uint8_t* report;   /* in */
    size_t reportSize; /* in */
} oe_verify_report_args_t;

/*
**==============================================================================
**
** _oe_get_revocation_info_args
**
**==============================================================================
*/
typedef struct _oe_get_revocation_info_args
{
    oe_result_t result;              /* out */
    uint8_t fmspc[6];                /* in */
    const char* crl_urls[3];         /* in */
    uint32_t num_crl_urls;           /* in */
    uint8_t* tcb_info;               /* out */
    size_t tcb_info_size;            /* out */
    uint8_t* tcb_issuer_chain;       /* out */
    size_t tcb_issuer_chain_size;    /* out */
    uint8_t* crl[3];                 /* out */
    size_t crl_size[3];              /* out */
    uint8_t* crl_issuer_chain[3];    /* out */
    size_t crl_issuer_chain_size[3]; /* out */

    // Memory allocated by host to pass outputs back to the enclave. Enclave
    // must free this memory via oe_host_free.
    uint8_t* host_out_buffer; /* out */
} oe_get_revocation_info_args_t;

#endif //_OE_INCLUDE_REPORT_H_
