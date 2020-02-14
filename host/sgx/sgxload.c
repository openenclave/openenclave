// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgxload.h"
#include <sgx_enclave_common.h>

#if defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <assert.h>
#include <openenclave/bits/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../memalign.h"
#include "../signkey.h"
#include "enclave.h"
#include "sgxmeasure.h"
#include "xstate.h"

static int _make_memory_protect_param(uint64_t inflags, bool simulate)
{
    int outflags = 0;

    if (inflags & SGX_SECINFO_TCS)
    {
        if (simulate)
        {
/* TCS can be read and written in simulation mode */
#if defined(__linux__)
            outflags = PROT_READ | PROT_WRITE;
#elif defined(_WIN32)
            outflags = PAGE_READWRITE;
#endif
        }
        else
        {
            outflags = ENCLAVE_PAGE_THREAD_CONTROL | ENCLAVE_PAGE_READ |
                       ENCLAVE_PAGE_WRITE;
        }
    }
    else if (inflags & SGX_SECINFO_REG)
    {
        if (!simulate)
        {
            if (inflags & SGX_SECINFO_R)
                outflags |= ENCLAVE_PAGE_READ;

            if (inflags & SGX_SECINFO_W)
                outflags |= ENCLAVE_PAGE_WRITE;

            if (inflags & SGX_SECINFO_X)
                outflags |= ENCLAVE_PAGE_EXECUTE;
        }
        else
        /* simulation mode falls back to OS memory protection settings */
        {
#if defined(__linux__)
            if (inflags & SGX_SECINFO_R)
                outflags |= PROT_READ;

            if (inflags & SGX_SECINFO_W)
                outflags |= PROT_WRITE;

            if (inflags & SGX_SECINFO_X)
                outflags |= PROT_EXEC;
#elif defined(_WIN32)
            if ((inflags & SGX_SECINFO_X) && (inflags & SGX_SECINFO_R) &&
                (inflags & SGX_SECINFO_W))
            {
                outflags = PAGE_EXECUTE_READWRITE;
            }
            else if ((inflags & SGX_SECINFO_X) && (inflags & SGX_SECINFO_R))
                outflags = PAGE_EXECUTE_READ;
            else if ((inflags & SGX_SECINFO_X))
                outflags = PAGE_EXECUTE;
            else if ((inflags & SGX_SECINFO_R) && (inflags & SGX_SECINFO_W))
                outflags = PAGE_READWRITE;
            else if ((inflags & SGX_SECINFO_R))
                outflags = PAGE_READONLY;
            else
                outflags = PAGE_NOACCESS;
#endif
        }
    }

#if defined(__linux__)
    if (simulate)
    {
        // GDB cannot set breakpoints in write protected pages.
        // Therefore in simulation mode, enable write to pages so that GDB can
        // insert breakpoints (int 3 instruction). Note: PROT_WRITE means enable
        // page write.
        outflags |= PROT_WRITE;
    }
#endif

    return outflags;
}

/* Detect the XSave Feature Request Mask (XFRM) to set in the enclave */
static uint64_t _detect_xfrm()
{
    uint64_t xfrm = SGX_ATTRIBUTES_DEFAULT_XFRM;
    // Enable AVX in the enclave if supported by the OS
    if ((oe_get_xfrm() & SGX_XFRM_AVX) == SGX_XFRM_AVX)
        xfrm |= SGX_XFRM_AVX;

    OE_TRACE_INFO("Value of XFRM to be set in enclave is %d\n", xfrm);
    return xfrm;
}

/* Set the SGX Enclave Control Structure (SECS) for the enclave */
static sgx_secs_t* _new_secs(
    uint64_t base,
    size_t size,
    const oe_sgx_load_context_t* context)
{
    sgx_secs_t* secs = NULL;

    if (!(secs = (sgx_secs_t*)oe_memalign(OE_PAGE_SIZE, sizeof(sgx_secs_t))))
        return NULL;

    memset(secs, 0, sizeof(sgx_secs_t));
    secs->size = size;
    secs->base = base;

    secs->flags = SGX_FLAGS_MODE64BIT;
    if (oe_sgx_is_debug_load_context(context))
        secs->flags |= SGX_FLAGS_DEBUG;

    /* what the driver sees with SGX SDK */
    secs->xfrm = context->attributes.xfrm;

    /* COMMENT1: ssaframesize hardcoded to one for now */
    secs->ssaframesize = 1;

    /* secs->flags |= SGX_FLAGS_EINITTOKEN_KEY; */
    /* secs->flags |= SGX_FLAGS_PROVISION_KEY; */

    return secs;
}

/*
** Allocate memory for an enclave so that it has the following layout:
**
**    [............xxxxxxxxxxxxxxxxxxxxxxxx...............]
**     ^           ^                       ^              ^
**    MPTR        BASE                 BASE+SIZE      MPTR+SIZE*2
**
**    [MPTR...BASE]                 - unused
**    [BASE...BASE+SIZE]            - used
**    [BASE+SIZE...MPTR+SIZE*2]     - unused
*/
static void* _allocate_enclave_memory(size_t enclave_size, int fd)
{
#if defined(__linux__)

    /* Allocate enclave memory for simulated and real mode */
    void* result = NULL;
    void* base = NULL;
    void* mptr = MAP_FAILED;

    /* Map memory region */
    {
        int mprot = PROT_READ | PROT_WRITE | PROT_EXEC;
        int mflags = MAP_SHARED;
        uint64_t mmap_size = enclave_size;

        /* If no file descriptor, then perform anonymous mapping and double
         * the allocation size, so that BASE can be aligned on the SIZE
         * boundary. This isn't neccessary on hardware backed enclaves, since
         * the driver will do the alignment. */
        if (fd == -1)
        {
            mflags |= MAP_ANONYMOUS;
            if (oe_safe_mul_u64(mmap_size, 2, &mmap_size) != OE_OK)
            {
                OE_TRACE_ERROR(
                    "oe_safe_mul_u64 failed mmap_size = %ld", mmap_size);
                goto done;
            }
        }

        mptr = mmap(NULL, mmap_size, mprot, mflags, fd, 0);
        if (mptr == MAP_FAILED)
        {
            OE_TRACE_ERROR(
                "mmap failed mmap_size=%ld mflags=0x%x", mmap_size, mflags);
            goto done;
        }

        /* Exit early in hardware backed enclaves, since it's aligned. */
        if (fd > -1)
        {
            assert((uintptr_t)mptr % mmap_size == 0);
            result = mptr;
            goto done;
        }
    }

    /* Align BASE on a boundary of SIZE */
    {
        uint64_t n = enclave_size;
        uint64_t addr = ((uint64_t)mptr + (n - 1)) / n * n;
        base = (void*)addr;
    }

    /* Unmap [MPTR...BASE] */
    {
        uint8_t* start = (uint8_t*)mptr;
        uint8_t* end = (uint8_t*)base;

        if (start != end && munmap(start, (size_t)(end - start)) != 0)
        {
            OE_TRACE_ERROR(
                "Unmap [MPTR...BASE] failed start=0x%p end=0x%p", start, end);
            goto done;
        }
    }

    /* Unmap [BASE+SIZE...MPTR+SIZE*2] */
    {
        uint8_t* start = (uint8_t*)base + enclave_size;
        uint8_t* end = (uint8_t*)mptr + enclave_size * 2;

        if (start != end && munmap(start, (size_t)(end - start)) != 0)
        {
            OE_TRACE_ERROR(
                "Unmap [BASE+SIZE...MPTR+SIZE*2] failed start=0x%p end=0x%p",
                start,
                end);
            goto done;
        }
    }

    result = base;

done:

    /* On failure, unmap initially allocated region.
     * Linux will handle already unmapped regions within this original range */
    if (!result && mptr != MAP_FAILED)
        munmap(mptr, enclave_size * 2);

    return result;

#elif defined(_WIN32)
    OE_UNUSED(fd);

    /* Allocate enclave memory for simulated mode only */
    void* result = NULL;

    /* Allocate virtual memory for this enclave */
    if (!(result = VirtualAlloc(
              NULL,
              enclave_size,
              MEM_COMMIT | MEM_RESERVE,
              PAGE_EXECUTE_READWRITE)))
    {
        OE_TRACE_ERROR("VirtualAlloc failed enclave_size=0x%lx", enclave_size);
        goto done;
    }

done:

    return result;

#endif /* defined(_WIN32) */
}

static oe_result_t _sgx_free_enclave_memory(
    void* addr,
    size_t size,
    bool is_simulation)
{
    OE_UNUSED(size);

    if (!is_simulation)
    {
        uint32_t enclave_error = 0;
        if (!enclave_delete(addr, &enclave_error) || enclave_error != 0)
        {
            OE_TRACE_ERROR(
                "enclave_delete failed with enclave_error=%d", enclave_error);
            return OE_PLATFORM_ERROR;
        }
    }
    else /* Fallthrough to simulation mode cleanup based on OS. */
    {
        OE_UNUSED(is_simulation);
#if defined(__linux__)
        /* munmap memory created for either AESM or simulation enclave */
        munmap(addr, size);
#elif defined(_WIN32)
        /* VirtualFree is used for enclave addr return by CreateEnclave and
           simulation enclave allocated by VirtualAlloc */
        VirtualFree(addr, 0, MEM_RELEASE);
#endif
    }

    return OE_OK;
}

static oe_result_t _get_sig_struct(
    const oe_sgx_enclave_properties_t* properties,
    const OE_SHA256* mrenclave,
    sgx_sigstruct_t* sigstruct)
{
    oe_result_t result = OE_UNEXPECTED;

    memset(sigstruct, 0, sizeof(sgx_sigstruct_t));

    /* If sigstruct doesn't have expected header, treat enclave as unsigned */
    if (memcmp(
            ((sgx_sigstruct_t*)properties->sigstruct)->header,
            SGX_SIGSTRUCT_HEADER,
            sizeof(SGX_SIGSTRUCT_HEADER)) != 0)
    {
        /* Only debug-sign unsigned enclaves in debug mode, fail otherwise */
        if (!(properties->config.attributes & SGX_FLAGS_DEBUG))
            OE_RAISE_MSG(
                OE_FAILURE,
                "Failed enclave was not signed with debug flag",
                NULL);

        /* Perform debug-signing with well-known debug-signing key */
        OE_CHECK(oe_sgx_sign_enclave(
            mrenclave,
            properties->config.attributes,
            properties->config.product_id,
            properties->config.security_version,
            OE_DEBUG_SIGN_KEY,
            OE_DEBUG_SIGN_KEY_SIZE,
            sigstruct));
    }
    else
    {
        /* Otherwise, treat enclave as signed and use its sigstruct */
        OE_CHECK(oe_memcpy_s(
            sigstruct,
            sizeof(sgx_sigstruct_t),
            properties->sigstruct,
            sizeof(sgx_sigstruct_t)));
    }

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_sgx_initialize_load_context(
    oe_sgx_load_context_t* context,
    oe_sgx_load_type_t type,
    uint64_t attributes)
{
    oe_result_t result = OE_UNEXPECTED;

    if (context)
        memset(context, 0, sizeof(oe_sgx_load_context_t));
    if (!context || type == OE_SGX_LOAD_TYPE_UNDEFINED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Set attributes before checking context properties */
    context->type = type;
    context->attributes.flags = attributes;
    context->attributes.xfrm = _detect_xfrm();

    context->dev = OE_SGX_NO_DEVICE_HANDLE;

    context->state = OE_SGX_LOAD_STATE_INITIALIZED;
    result = OE_OK;

done:
    return result;
}

void oe_sgx_cleanup_load_context(oe_sgx_load_context_t* context)
{
    /* Clear all fields, this also sets state to undefined */
    memset(context, 0, sizeof(oe_sgx_load_context_t));
}

oe_result_t oe_sgx_create_enclave(
    oe_sgx_load_context_t* context,
    size_t enclave_size,
    uint64_t* enclave_addr)
{
    oe_result_t result = OE_UNEXPECTED;
    void* base = NULL;
    sgx_secs_t* secs = NULL;

    if (enclave_addr)
        *enclave_addr = 0;

    if (!context || !enclave_size || !enclave_addr)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOAD_STATE_INITIALIZED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* SIZE must be a power of two */
    if (enclave_size != oe_round_u64_to_pow2(enclave_size))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Only allocate memory if we are creating an enclave in either simulation
     * mode or on Linux Kabylake machines. */
    if (context->type == OE_SGX_LOAD_TYPE_CREATE)
    {
        if (oe_sgx_is_simulation_load_context(context))
        {
            /* Allocation memory-mapped region */
            if (!(base = _allocate_enclave_memory(enclave_size, context->dev)))
                OE_RAISE(OE_OUT_OF_MEMORY);
        }
    }

    /* Create SECS structure */
    if (!(secs = _new_secs((uint64_t)base, enclave_size, context)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Measure this operation */
    OE_CHECK(oe_sgx_measure_create_enclave(&context->hash_context, secs));

    if (context->type == OE_SGX_LOAD_TYPE_MEASURE)
    {
        /* Use this phony base address when signing enclaves */
        base = (void*)0x0000ffff00000000;
    }
    else if (oe_sgx_is_simulation_load_context(context))
    {
        /* Simulate enclave creation */
        context->sim.addr = (void*)secs->base;
        context->sim.size = secs->size;
    }
    else
    {
        uint32_t enclave_error;
        void* base = enclave_create(
            NULL, /* Let OS choose the enclave base address */
            secs->size,
            secs->size,
            ENCLAVE_TYPE_SGX1,
            (const void*)secs,
            sizeof(sgx_secs_t),
            &enclave_error);

        if (!base)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "enclave_create with ENCLAVE_TYPE_SGX1 type failed (err=%#x)",
                enclave_error);

        secs->base = (uint64_t)base;
    }

    *enclave_addr = base ? (uint64_t)base : secs->base;
    context->state = OE_SGX_LOAD_STATE_ENCLAVE_CREATED;
    result = OE_OK;

done:

    //  free enclave  memory
    if (result != OE_OK && context != NULL &&
        context->type == OE_SGX_LOAD_TYPE_CREATE && base != NULL)
    {
        _sgx_free_enclave_memory(
            base, enclave_size, oe_sgx_is_simulation_load_context(context));
    }

    if (secs)
        oe_memalign_free(secs);

    return result;
}

#if defined(OE_TRACE_MEASURE)

const char* hex_map = "0123456789abcdef";

#define hexof(x) hex_map[((x) >> 4) & 0xf], hex_map[(x)&0xf]
static void _dump_page(uint64_t src)

{
    uint8_t* ptr = (uint8_t*)src;
    for (int i = 0; i < OE_PAGE_SIZE;)
    {
        printf(
            "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%"
            "c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
            hexof(ptr[i + 0x00]),
            hexof(ptr[i + 0x01]),
            hexof(ptr[i + 0x02]),
            hexof(ptr[i + 0x03]),
            hexof(ptr[i + 0x04]),
            hexof(ptr[i + 0x05]),
            hexof(ptr[i + 0x06]),
            hexof(ptr[i + 0x07]),
            hexof(ptr[i + 0x08]),
            hexof(ptr[i + 0x09]),
            hexof(ptr[i + 0x0a]),
            hexof(ptr[i + 0x0b]),
            hexof(ptr[i + 0x0c]),
            hexof(ptr[i + 0x0d]),
            hexof(ptr[i + 0x0e]),
            hexof(ptr[i + 0x0f]),
            hexof(ptr[i + 0x10]),
            hexof(ptr[i + 0x11]),
            hexof(ptr[i + 0x12]),
            hexof(ptr[i + 0x13]),
            hexof(ptr[i + 0x14]),
            hexof(ptr[i + 0x15]),
            hexof(ptr[i + 0x16]),
            hexof(ptr[i + 0x17]),
            hexof(ptr[i + 0x18]),
            hexof(ptr[i + 0x19]),
            hexof(ptr[i + 0x1a]),
            hexof(ptr[i + 0x1b]),
            hexof(ptr[i + 0x1c]),
            hexof(ptr[i + 0x1d]),
            hexof(ptr[i + 0x1e]),
            hexof(ptr[i + 0x1f]));
        i += 0x20;
        printf(
            "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%"
            "c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
            hexof(ptr[i + 0x00]),
            hexof(ptr[i + 0x01]),
            hexof(ptr[i + 0x02]),
            hexof(ptr[i + 0x03]),
            hexof(ptr[i + 0x04]),
            hexof(ptr[i + 0x05]),
            hexof(ptr[i + 0x06]),
            hexof(ptr[i + 0x07]),
            hexof(ptr[i + 0x08]),
            hexof(ptr[i + 0x09]),
            hexof(ptr[i + 0x0a]),
            hexof(ptr[i + 0x0b]),
            hexof(ptr[i + 0x0c]),
            hexof(ptr[i + 0x0d]),
            hexof(ptr[i + 0x0e]),
            hexof(ptr[i + 0x0f]),
            hexof(ptr[i + 0x10]),
            hexof(ptr[i + 0x11]),
            hexof(ptr[i + 0x12]),
            hexof(ptr[i + 0x13]),
            hexof(ptr[i + 0x14]),
            hexof(ptr[i + 0x15]),
            hexof(ptr[i + 0x16]),
            hexof(ptr[i + 0x17]),
            hexof(ptr[i + 0x18]),
            hexof(ptr[i + 0x19]),
            hexof(ptr[i + 0x1a]),
            hexof(ptr[i + 0x1b]),
            hexof(ptr[i + 0x1c]),
            hexof(ptr[i + 0x1d]),
            hexof(ptr[i + 0x1e]),
            hexof(ptr[i + 0x1f]));
        i += 0x20;
    }
}

static void _dump_load_enclave_data(
    uint64_t offset,
    uint64_t flags,
    uint64_t src,
    bool extend)

{
    printf(
        "========== load_enclave_data offset=%x, flags=%x, extend=%d "
        "============\n",
        (uint32_t)offset,
        (uint32_t)flags,
        extend);
    _dump_page(src);
}

#endif /* defined(OE_TRACE_MEASURE) */

oe_result_t oe_sgx_load_enclave_data(
    oe_sgx_load_context_t* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!context || !base || !addr || !src || !flags)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOAD_STATE_ENCLAVE_CREATED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* addr and src must both be page aligned */
    if (addr % OE_PAGE_SIZE || src % OE_PAGE_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(OE_TRACE_MEASURE)

    _dump_load_enclave_data(addr - base, flags, src, extend);

#endif /* defined(OE_TRACE_MEASURE) */

    /* Measure this operation */
    OE_CHECK(oe_sgx_measure_load_enclave_data(
        &context->hash_context, base, addr, src, flags, extend));

    if (context->type == OE_SGX_LOAD_TYPE_MEASURE)
    {
        /* EADD has no further action in measurement mode */
        result = OE_OK;
        goto done;
    }
    else if (oe_sgx_is_simulation_load_context(context))
    {
        /* Simulate enclave add page */
        /* Verify that page is within enclave boundaries */
        if ((void*)addr < context->sim.addr ||
            (uint8_t*)addr >
                (uint8_t*)context->sim.addr + context->sim.size - OE_PAGE_SIZE)
            OE_RAISE_MSG(
                OE_FAILURE, "Page is NOT within enclave boundaries", NULL);

        /* Copy page contents onto memory-mapped region */
        OE_CHECK(oe_memcpy_s(
            (uint8_t*)addr, OE_PAGE_SIZE, (uint8_t*)src, OE_PAGE_SIZE));

        /* Set page access permissions */
        {
            int prot = _make_memory_protect_param(flags, true /*simulate*/);

            if ((uint32_t)prot > OE_INT_MAX)
                OE_RAISE_MSG(
                    OE_FAILURE, "Unexpected page protections: %#x", prot);

#if defined(__linux__)
            if (mprotect((void*)addr, OE_PAGE_SIZE, prot) != 0)
                OE_RAISE_MSG(
                    OE_FAILURE,
                    "mprotect failed (addr=%#x, prot=%#x)",
                    addr,
                    prot);
#elif defined(_WIN32)
            DWORD old;
            if (!VirtualProtect((LPVOID)addr, OE_PAGE_SIZE, prot, &old))
                OE_RAISE_MSG(
                    OE_FAILURE,
                    "VirtualProtect failed (addr=%#x, prot=%#x)",
                    addr,
                    prot);
#endif
        }
    }
    else
    {
        int protect = _make_memory_protect_param(flags, false /*not simulate*/);
        if (!extend)
            protect |= ENCLAVE_PAGE_UNVALIDATED;

        uint32_t enclave_error;
        if (enclave_load_data(
                (void*)addr,
                OE_PAGE_SIZE,
                (const void*)src,
                (uint32_t)protect,
                &enclave_error) != OE_PAGE_SIZE)
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "enclave_load_data failed (addr=%#x, prot=%#x, err=%#x)",
                addr,
                protect,
                enclave_error);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_initialize_enclave(
    oe_sgx_load_context_t* context,
    uint64_t addr,
    const oe_sgx_enclave_properties_t* properties,
    OE_SHA256* mrenclave)
{
    oe_result_t result = OE_UNEXPECTED;

    if (mrenclave)
        memset(mrenclave, 0, sizeof(OE_SHA256));

    if (!context || !addr || !properties || !mrenclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOAD_STATE_ENCLAVE_CREATED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Measure this operation */
    OE_CHECK(
        oe_sgx_measure_initialize_enclave(&context->hash_context, mrenclave));

    /* EINIT has no further action in measurement/simulation mode */
    if (context->type == OE_SGX_LOAD_TYPE_CREATE &&
        !oe_sgx_is_simulation_load_context(context))
    {
        /* Get a debug sigstruct for MRENCLAVE if necessary */
        sgx_sigstruct_t sigstruct;
        OE_CHECK(_get_sig_struct(properties, mrenclave, &sigstruct));

        uint32_t enclave_error = 0;
        if (!enclave_initialize(
                (void*)addr,
                (const void*)&sigstruct,
                sizeof(sgx_sigstruct_t),
                &enclave_error))
            OE_RAISE_MSG(
                OE_PLATFORM_ERROR,
                "enclave_initialize failed (err=%#x)",
                enclave_error);
    }

    context->state = OE_SGX_LOAD_STATE_ENCLAVE_INITIALIZED;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_delete_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* free allocate memory. */
    OE_CHECK(_sgx_free_enclave_memory(
        (void*)enclave->addr, enclave->size, enclave->simulate));
    result = OE_OK;
done:
    return result;
}
