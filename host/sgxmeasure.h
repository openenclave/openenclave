// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXMEASURE_H
#define _OE_SGXMEASURE_H

#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/sha.h>

OE_EXTERNC_BEGIN

OE_Result OE_SGXMeasureCreateEnclave(OE_SHA256Context* context, SGX_Secs* secs);

OE_Result OE_SGXMeasureLoadEnclaveData(
    OE_SHA256Context* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

OE_Result OE_SGXMeasureInitializeEnclave(
    OE_SHA256Context* context,
    OE_SHA256* mrenclave);

OE_EXTERNC_END

#endif /* _OE_SGXMEASURE_H */
