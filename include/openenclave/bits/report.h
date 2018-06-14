// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_REPORT_H_
#define _OE_BITS_REPORT_H_

#include <openenclave/types.h>

/*
**==============================================================================
**
** OE_InitQuoteArgs
**
**==============================================================================
*/
typedef struct _OE_InitQuoteArgs
{
    OE_Result result;
    SGX_TargetInfo targetInfo;
    SGX_EPIDGroupID epidGroupID;
} OE_InitQuoteArgs;

/*
**==============================================================================
**
** OE_GetQETargetInfoArgs
**
**==============================================================================
*/
typedef struct _OE_GetQETargetInfoArgs
{
    OE_Result result;
    SGX_TargetInfo targetInfo;
} OE_GetQETargetInfoArgs;

/*
**==============================================================================
**
** _OE_GetQuoteArgs
**
**==============================================================================
*/
typedef struct _OE_GetQuoteArgs
{
    OE_Result result;
    SGX_Report sgxReport;
    uint32_t quoteSize;
    uint8_t quote[1];
} OE_GetQuoteArgs;

/*
**==============================================================================
**
** OE_GetReportArgs
**
**==============================================================================
*/
typedef struct _OE_GetReportArgs
{
    OE_Result result; /* out */

    uint32_t options; /* in */

    uint8_t optParams[sizeof(SGX_TargetInfo)]; /* in */
    uint32_t optParamsSize;                    /* in */

    uint8_t* reportBuffer;     /* ptr to output buffer */
    uint32_t reportBufferSize; /* in-out */
} OE_GetReportArgs;

/*
**==============================================================================
**
** OE_VerifyReportArgs
**
**==============================================================================
*/
typedef struct _OE_VerifyReportArgs
{
    OE_Result result; /* out */

    uint8_t* report;     /* in */
    uint32_t reportSize; /* in */
} OE_VerifyReportArgs;

#endif //_OE_BITS_REPORT_H_