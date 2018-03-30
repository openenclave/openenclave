// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXDEV_H
#define _OE_SGXDEV_H

#include <openenclave/bits/sha.h>
#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

#define SGX_DRIVER_MAGIC 0x50e9343f
#define SGX_MEASURER_MAGIC 0x4c6b6236

typedef struct _OE_SGXDevice OE_SGXDevice;

typedef OE_Result (*OE_ECreateProc)(
    OE_SGXDevice* dev,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr);

typedef OE_Result (*OE_EAddProc)(
    OE_SGXDevice* dev,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

typedef OE_Result (*OE_EInitProc)(
    OE_SGXDevice* dev,
    uint64_t addr,
    const SGX_SigStruct* sigstruct);

typedef OE_Result (*OE_GetHash)(OE_SGXDevice* dev, OE_SHA256* hash);

typedef OE_Result (*OE_CloseProc)(OE_SGXDevice* dev);

typedef uint32_t (*OE_GetMagic)(const OE_SGXDevice* dev);

struct _OE_SGXDevice
{
    OE_ECreateProc ecreate;
    OE_EAddProc eadd;
    OE_EInitProc einit;
    OE_GetHash gethash;
    OE_CloseProc close;
    OE_GetMagic getmagic;
};

OE_EXTERNC_END

#endif /* _OE_SGXDEV_H */
