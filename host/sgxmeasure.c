// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "sgxmeasure.h"
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>

static void _MeasureZeros(OE_SHA256Context* context, size_t size)
{
    char zeros[128] = {0};

    while (size)
    {
        if (size < sizeof(zeros))
        {
            OE_SHA256Update(context, zeros, size);
            size -= size;
        }
        else
        {
            OE_SHA256Update(context, zeros, sizeof(zeros));
            size -= sizeof(zeros);
        }
    }
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
        _MeasureZeros(context, 48);
        OE_SHA256Update(context, (const uint8_t*)page + pgoff, CHUNK_SIZE);
    }
}

OE_Result OE_SGXMeasureCreateEnclave(OE_SHA256Context* context, SGX_Secs* secs)
{
    OE_Result result = OE_UNEXPECTED;

    if (!context || !secs)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize measurement */
    OE_SHA256Init(context);

    /* Measure ECREATE */
    OE_SHA256Update(context, "ECREATE", 8);
    OE_SHA256Update(context, &secs->ssaframesize, sizeof(uint32_t));
    OE_SHA256Update(context, &secs->size, sizeof(uint64_t));
    _MeasureZeros(context, 44);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_SGXMeasureLoadEnclaveData(
    OE_SHA256Context* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    OE_Result result = OE_UNEXPECTED;
    uint64_t vaddr = addr - base;

    if (!context || !base || !addr || !src || !flags || addr < base)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Measure EADD */
    OE_SHA256Update(context, "EADD\0\0\0", 8);
    OE_SHA256Update(context, &vaddr, sizeof(vaddr));
    OE_SHA256Update(context, &flags, sizeof(flags));
    _MeasureZeros(context, 40);

    /* Measure EEXTEND if requested */
    if (extend)
        _MeasureEExtend(context, vaddr, flags, (void*)src);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_SGXMeasureInitializeEnclave(
    OE_SHA256Context* context,
    OE_SHA256* mrenclave)
{
    OE_Result result = OE_UNEXPECTED;

    if (!context || !mrenclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Finalize measurement like EINIT */
    OE_SHA256Final(context, mrenclave);

    result = OE_OK;

done:
    return result;
}
