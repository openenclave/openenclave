// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXCERTEXTENSIONS_H
#define _OE_SGXCERTEXTENSIONS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>

OE_EXTERNC_BEGIN

typedef struct _ParsedExtensionInfo
{
    uint8_t* ppid;
    uint32_t ppidLength;
    uint8_t* tcb;
    uint32_t tcbSize;
    uint8_t* tcbCompSvn[17];
    uint32_t tcbCompSvnSize[17];
    uint8_t* pceSvn;
    uint32_t pceSvnSize;
    uint8_t* cpuSvn;
    uint32_t cpuSvnSize;
    uint8_t* pceId;
    uint32_t pceIdSize;
    uint8_t* fmspc;
    uint32_t fmspcSize;
    uint8_t* sgxType;
    uint32_t sgxTypeSize;
    uint16_t success;
    uint16_t errors;
} ParsedExtensionInfo;

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    uint32_t* bufferSize,
    ParsedExtensionInfo* parsedInfo);

OE_EXTERNC_END

#endif // _OE_SGXCERTEXTENSIONS_H
