// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXLOAD_H
#define _OE_SGXLOAD_H

#include <openenclave/host.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxtypes.h>

OE_EXTERNC_BEGIN

#define OE_SGX_NO_DEVICE_HANDLE -1

OE_INLINE bool OE_SGXLoadIsSimulation(const OE_SGXLoadContext* context)
{
    return (context && (context->attributes & OE_ENCLAVE_FLAG_SIMULATE));
}

OE_INLINE bool OE_SGXLoadIsDebug(const OE_SGXLoadContext* context)
{
    return (context && (context->attributes & OE_ENCLAVE_FLAG_DEBUG));
}

OE_Result OE_SGXCreateEnclave(
    OE_SGXLoadContext* context,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr);

OE_Result OE_SGXLoadEnclaveData(
    OE_SGXLoadContext* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

OE_Result OE_SGXInitializeEnclave(
    OE_SGXLoadContext* context,
    uint64_t addr,
    const OE_SGXEnclaveProperties* properties,
    OE_SHA256* mrenclave);

OE_EXTERNC_END

#endif /* _OE_SGXLOAD_H */
