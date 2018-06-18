// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_REPORT_H_
#define _OE_INCLUDE_REPORT_H_

#include <openenclave/bits/types.h>

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
    uint32_t quoteSize;
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

    uint32_t options; /* in */

    uint8_t optParams[sizeof(sgx_target_info_t)]; /* in */
    uint32_t optParamsSize;                    /* in */

    uint8_t* reportBuffer;     /* ptr to output buffer */
    uint32_t reportBufferSize; /* in-out */
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

    uint8_t* report;     /* in */
    uint32_t reportSize; /* in */
} oe_verify_report_args_t;

#endif //_OE_INCLUDE_REPORT_H_