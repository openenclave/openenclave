// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TCBINFO_H
#define _OE_COMMON_TCBINFO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef enum _OE_Tcb_Status {
    OE_TCB_STATUS_REVOKED,
    OE_TCB_STATUS_OUT_OF_DATE,
    OE_TCB_STATUS_UP_TO_DATE
} OE_Tcb_Status;

typedef struct _OE_Tcb
{
    uint64_t sgxTCBCompSvn[16];
    uint64_t pceSvn;
    OE_Tcb_Status status;
} OE_Tcb;

typedef struct _OE_ParsedTcbInfo
{
    uint32_t version;
    const uint8_t* issueDate;
    uint32_t issueDateSize;
    const uint8_t* fmspc;
    uint32_t fmspcSize;
    OE_Tcb tcbLevels[3];
    const uint8_t* signature;
    uint32_t signatureSize;
} OE_ParsedTcbInfo;

oe_result_t OE_ParseTCBInfo(
    const uint8_t* tcbInfoJson,
    uint32_t tcbInfoJsonSize,
    OE_ParsedTcbInfo* parsedInfo);

OE_EXTERNC_END

#endif // _OE_COMMON_TCBINFO_H
