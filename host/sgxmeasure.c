// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if 0
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>

typedef struct _OE_SGXMeasurer
{
    OE_SGXDevice base;
    unsigned int magic;
    OE_SHA256Context context;
    OE_SHA256 hash;
} OE_SGXMeasurer;

static int _Ok(const OE_SGXMeasurer* driver)
{
    return driver && driver->magic == SGX_MEASURER_MAGIC;
}

static void _MeasureECreate(OE_SHA256Context* context, uint64_t enclaveSize)
{
    const uint32_t ssaframesize = 1;

    OE_SHA256Update(context, "ECREATE", 8);
    OE_SHA256Update(context, &ssaframesize, sizeof(uint32_t));
    OE_SHA256Update(context, &enclaveSize, sizeof(uint64_t));
    OE_SHA256UpdateZeros(context, 44);
}

static void _MeasureEExtend(
    OE_SHA256Context* context,
    uint64_t vaddr,
    uint64_t flags,
    const void* page)
{
    uint64_t pgoff = 0;
    const uint64_t CHUNK_SIZE = 256;

    /* Write this page one chunk at a time */
    for (pgoff = 0; pgoff < OE_PAGE_SIZE; pgoff += CHUNK_SIZE)
    {
        const uint64_t moffset = vaddr + pgoff;

        OE_SHA256Update(context, "EEXTEND", 8);
        OE_SHA256Update(context, &moffset, sizeof(moffset));
        OE_SHA256UpdateZeros(context, 48);
        OE_SHA256Update(context, (const uint8_t*)page + pgoff, CHUNK_SIZE);
    }
}

static void _MeasureEAdd(
    OE_SHA256Context* context,
    uint64_t vaddr,
    uint64_t flags,
    bool extend,
    const void* page)
{
    OE_SHA256Update(context, "EADD\0\0\0", 8);
    OE_SHA256Update(context, &vaddr, sizeof(vaddr));
    OE_SHA256Update(context, &flags, sizeof(flags));
    OE_SHA256UpdateZeros(context, 40);

    if (extend)
        _MeasureEExtend(context, vaddr, flags, page);
}

static OE_Result _ECreateProc(
    OE_SGXDevice* dev,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr)
{
    OE_SGXMeasurer* self = (OE_SGXMeasurer*)dev;
    OE_Result result = OE_UNEXPECTED;

    if (enclaveAddr)
        *enclaveAddr = 0;

    if (!_Ok(self) || !enclaveSize || !enclaveAddr)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize measurement */
    OE_SHA256Init(&self->context);

    /* Measure ECREATE */
    _MeasureECreate(&self->context, enclaveSize);

    /* Create a phony address */
    *enclaveAddr = (uint64_t)0xffffffff00000000;

    result = OE_OK;

OE_CATCH:

    return result;
}

static OE_Result _EAddProc(
    OE_SGXDevice* dev,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SGXMeasurer* self = (OE_SGXMeasurer*)dev;
    uint64_t vaddr = addr - base;

    if (!_Ok(self) || !base || !addr || !src || !flags)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    _MeasureEAdd(&self->context, vaddr, flags, extend, (void*)src);

    result = OE_OK;

OE_CATCH:

    return result;
}

static OE_Result _EInitProc(
    OE_SGXDevice* dev,
    uint64_t addr,
    const SGX_SigStruct* sigstruct)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SGXMeasurer* self = (OE_SGXMeasurer*)dev;

    if (!_Ok(self) || !addr)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Finalize the measurement */
    OE_SHA256Final(&self->context, &self->hash);

    result = OE_OK;

OE_CATCH:

    return result;
}

static OE_Result _GetHashProc(OE_SGXDevice* dev, OE_SHA256* hash)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SGXMeasurer* self = (OE_SGXMeasurer*)dev;

    if (!_Ok(self))
        OE_THROW(OE_INVALID_PARAMETER);

    memcpy(hash, &self->hash, sizeof(OE_SHA256));

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _CloseProc(OE_SGXDevice* dev)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SGXMeasurer* self = (OE_SGXMeasurer*)dev;

    if (!_Ok(self))
        OE_THROW(OE_INVALID_PARAMETER);

    free(self);

    result = OE_OK;

OE_CATCH:
    return result;
}

static uint32_t _GetMagic(const OE_SGXDevice* dev)
{
    OE_SGXMeasurer* self = (OE_SGXMeasurer*)dev;

    if (!_Ok(self))
        return 0;

    return self->magic;
}

OE_SGXDevice* __OE_OpenSGXMeasurer()
{
    OE_SGXDevice* result = NULL;
    OE_SGXMeasurer* self;

    if (!(self = (OE_SGXMeasurer*)calloc(1, sizeof(OE_SGXMeasurer))))
        goto catch;

    self->base.ecreate = _ECreateProc;
    self->base.eadd = _EAddProc;
    self->base.einit = _EInitProc;
    self->base.gethash = _GetHashProc;
    self->base.getmagic = _GetMagic;
    self->base.close = _CloseProc;
    self->magic = SGX_MEASURER_MAGIC;

    result = &self->base;

OE_CATCH:

    if (!result)
        free(self);

    return result;
}
