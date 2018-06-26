// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_TCBINFO_H
#define _OE_COMMON_TCBINFO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _TCBInfo
{
    uint32_t version;
    const char* issueDate;
    uint64_t compSVN[16];
    uint64_t pceSVN;
} TCBInfo;

oe_result_t OE_VerifyTCBInfo(
    const TCBInfo* info,
    const uint8_t* tcbInfoJson,
    uint32_t tcbInfoJsonSize);

OE_EXTERNC_END

#endif // _OE_COMMON_TCBINFO_H
