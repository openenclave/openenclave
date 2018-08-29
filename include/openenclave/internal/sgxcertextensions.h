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
    uint8_t ppid[16];
    uint8_t compSvn[16];
    uint16_t pceSvn;
    uint8_t cpuSvn[16];
    uint8_t pceId[2];
    uint8_t fmspc[6];
    uint8_t sgxType;
    bool optDynamicPlatform;
    bool optCachedKeys;
} ParsedExtensionInfo;

oe_result_t ParseSGXExtensions(
    oe_cert_t* cert,
    uint8_t* buffer,
    size_t* bufferSize,
    ParsedExtensionInfo* parsedInfo);

OE_EXTERNC_END

#endif // _OE_SGXCERTEXTENSIONS_H
