// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgxmeasure.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>

static void _measure_zeros(oe_sha256_context_t* context, size_t size)
{
    char zeros[128] = {0};

    while (size)
    {
        if (size < sizeof(zeros))
        {
            oe_sha256_update(context, zeros, size);
            size -= size;
        }
        else
        {
            oe_sha256_update(context, zeros, sizeof(zeros));
            size -= sizeof(zeros);
        }
    }
}

static void _measure_eextend(
    oe_sha256_context_t* context,
    uint64_t vaddr,
    uint64_t flags,
    const void* page)
{
    uint64_t pgoff = 0;
    const uint64_t CHUNK_SIZE = 256;
    OE_UNUSED(flags);

    /* Write this page one chunk at a time */
    for (pgoff = 0; pgoff < OE_PAGE_SIZE; pgoff += CHUNK_SIZE)
    {
        const uint64_t moffset = vaddr + pgoff;

        oe_sha256_update(context, "EEXTEND", 8);
        oe_sha256_update(context, &moffset, sizeof(moffset));
        _measure_zeros(context, 48);
        oe_sha256_update(context, (const uint8_t*)page + pgoff, CHUNK_SIZE);
    }
}

oe_result_t oe_sgx_measure_create_enclave(
    oe_sha256_context_t* context,
    sgx_secs_t* secs)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !secs)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize measurement */
    oe_sha256_init(context);

    /* Measure ECREATE */
    oe_sha256_update(context, "ECREATE", 8);
    oe_sha256_update(context, &secs->ssaframesize, sizeof(uint32_t));
    oe_sha256_update(context, &secs->size, sizeof(uint64_t));
    _measure_zeros(context, 44);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_measure_load_enclave_data(
    oe_sha256_context_t* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t vaddr = addr - base;

    if (!context || !base || !addr || !src || !flags || addr < base)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Measure EADD */
    oe_sha256_update(context, "EADD\0\0\0", 8);
    oe_sha256_update(context, &vaddr, sizeof(vaddr));
    oe_sha256_update(context, &flags, sizeof(flags));
    _measure_zeros(context, 40);

    /* Measure EEXTEND if requested */
    if (extend)
        _measure_eextend(context, vaddr, flags, (void*)src);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_measure_initialize_enclave(
    oe_sha256_context_t* context,
    OE_SHA256* mrenclave)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !mrenclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Finalize measurement like EINIT */
    oe_sha256_final(context, mrenclave);

    result = OE_OK;

done:
    return result;
}
