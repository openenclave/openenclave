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
    sgx_target_info_t target_info;
    sgx_epid_group_id_t epid_group_id;
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
    sgx_target_info_t target_info;
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
    sgx_report_t sgx_report;
    size_t quote_size;
    uint8_t quote[1];
} oe_get_quote_args_t;

/*
**==============================================================================
**
** oe_get_sgx_report_args_t
**
**==============================================================================
*/
typedef struct _oe_get_sgx_report_args
{
    oe_result_t result; /* out */

    uint8_t opt_params[sizeof(sgx_target_info_t)]; /* in */
    size_t opt_params_size;                        /* in */

    sgx_report_t sgx_report; /* out */
} oe_get_sgx_report_args_t;

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

    uint8_t* report;    /* in */
    size_t report_size; /* in */
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

/*
**==============================================================================
**
** _oe_get_qe_identity_info_args
**
**==============================================================================
*/
typedef struct _oe_get_qe_identity_info_args
{
    oe_result_t result;       /* out */
    uint8_t* qe_id_info;      /* out */
    size_t qe_id_info_size;   /* out */
    uint8_t* issuer_chain;    /* out */
    size_t issuer_chain_size; /* out */

    // Memory allocated by host to pass outputs back to the enclave. Enclave
    // must free this memory via oe_host_free.
    uint8_t* host_out_buffer; /* out */
} oe_get_qe_identity_info_args_t;

/*
**==============================================================================
**
** oe_report_type_t
**
**==============================================================================
*/
typedef enum _oe_report_type
{
    OE_REPORT_TYPE_SGX_LOCAL = 1,
    OE_REPORT_TYPE_SGX_REMOTE = 2,
    __OE_REPORT_TYPE_MAX = OE_ENUM_MAX
} oe_report_type_t;

/*
**==============================================================================
**
** oe_report_header_t
**
**==============================================================================
*/
typedef struct _oe_report_header
{
    uint32_t version;
    oe_report_type_t report_type;
    uint64_t report_size;
    uint8_t report[];
} oe_report_header_t;

OE_STATIC_ASSERT(sizeof(oe_report_header_t) == 16);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_report_header_t, report) == sizeof(oe_report_header_t));

#define OE_REPORT_HEADER_VERSION (1)

#endif //_OE_INCLUDE_REPORT_H_
