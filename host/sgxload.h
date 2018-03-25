// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXLOAD_H
#define _OE_SGXLOAD_H

#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/host.h>

OE_EXTERNC_BEGIN

#define OE_SGX_NO_DEVICE_HANDLE -1

OE_INLINE bool OE_IsContextSimulation(OE_SgxLoadContext* context)
{
    return (context && (context->attributes & OE_FLAG_SIMULATE));
}

OE_INLINE bool OE_IsContextDebug(OE_SgxLoadContext* context)
{
    return (context && (context->attributes & OE_FLAG_DEBUG));
}

/*
**==============================================================================
** SGX Enclave creation methods implemented by sgxload.c
**==============================================================================
*/
OE_Result OE_ECreate(
    OE_SgxLoadContext* context,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr);

OE_Result OE_EAdd(
    OE_SgxLoadContext* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

OE_Result OE_EInit(
    OE_SgxLoadContext* context,
    uint64_t addr,
    uint64_t sigstruct,
    uint64_t einittoken,
    OE_SHA256* mrenclave);

/*
**==============================================================================
** SGX Enclave measurement methods implemented by sgxmeasure.c
**==============================================================================
*/
OE_Result OE_MeasureECreate(OE_SHA256Context* context, SGX_Secs* secs);

OE_Result OE_MeasureEAdd(
    OE_SHA256Context* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

OE_Result OE_MeasureEInit(OE_SHA256Context* context, OE_SHA256* mrenclave);

OE_EXTERNC_END

#endif /* _OE_SGXLOAD_H */
