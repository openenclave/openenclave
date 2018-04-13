// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include "sgxload.h"
#if defined(__linux__)
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "linux/sgxioctl.h"
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <openenclave/bits/aesm.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include "memalign.h"

static uint32_t _MakeMemoryProtectParam(uint64_t inflags, bool simulate)
{
#if defined(__linux__)

    uint32_t outflags = 0;

    if (inflags & SGX_SECINFO_TCS)
    {
        if (simulate)
        {
            /* TCS can be read and written in simulation mode */
            outflags = PROT_READ | PROT_WRITE;
        }
        else
        {
            outflags = PROT_NONE;
        }
    }
    else if (inflags & SGX_SECINFO_REG)
    {
        if (inflags & SGX_SECINFO_R)
            outflags |= PROT_READ;

        if (inflags & SGX_SECINFO_W)
            outflags |= PROT_WRITE;

        if (inflags & SGX_SECINFO_X)
            outflags |= PROT_WRITE;
    }

    return outflags;

#elif defined(_WIN32)

    if (inflags & SGX_SECINFO_TCS)
    {
        if (simulate)
        {
            /* TCS can be read and written in simulation mode */
            return PAGE_READWRITE;
        }
        else
        {
            return PAGE_ENCLAVE_THREAD_CONTROL | PAGE_READWRITE;
        }
    }

    if (inflags & SGX_SECINFO_REG)
    {
        if ((inflags & SGX_SECINFO_X) && (inflags & SGX_SECINFO_R) &&
            (inflags & SGX_SECINFO_W))
        {
            return PAGE_EXECUTE_READWRITE;
        }

        if ((inflags & SGX_SECINFO_X) && (inflags & SGX_SECINFO_R))
        {
            return PAGE_EXECUTE_READ;
        }

        if ((inflags & SGX_SECINFO_X))
            return PAGE_EXECUTE;

        if ((inflags & SGX_SECINFO_R) && (inflags & SGX_SECINFO_W))
        {
            return PAGE_READWRITE;
        }

        if ((inflags & SGX_SECINFO_R))
            return PAGE_READONLY;
    }

    return PAGE_NOACCESS;

#endif
}

static SGX_Secs* _NewSecs(uint64_t base, uint64_t size, bool debug)
{
    SGX_Secs* secs = NULL;

    if (!(secs = (SGX_Secs*)OE_Memalign(OE_PAGE_SIZE, sizeof(SGX_Secs))))
        return NULL;

    memset(secs, 0, sizeof(SGX_Secs));
    secs->size = size;
    secs->base = base;

    secs->flags = SGX_FLAGS_MODE64BIT;
    if (debug)
        secs->flags |= SGX_FLAGS_DEBUG;

    /* what the driver sees with SGX SDK */
    secs->xfrm = SGX_ATTRIBUTES_DEFAULT_XFRM;

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
static void* _AllocateEnclaveMemory(uint64_t enclaveSize, int fd)
{
#if defined(__linux__)

    /* Allocate enclave memory for simulated and real mode */
    void* result = NULL;
    void* base = NULL;
    void* mptr = NULL;

    /* Map memory region */
    {
        int mprot = PROT_READ | PROT_WRITE | PROT_EXEC;
        int mflags = MAP_SHARED;

        /* If no file descriptor, then perform anonymous mapping */
        if (fd == -1)
            mflags |= MAP_ANONYMOUS;

        /* Allocate double so BASE can be aligned on SIZE boundary */
        mptr = mmap(NULL, enclaveSize * 2, mprot, mflags, fd, 0);

        if (mptr == MAP_FAILED)
            goto done;
    }

    /* Align BASE on a boundary of SIZE */
    {
        uint64_t n = enclaveSize;
        uint64_t addr = ((uint64_t)mptr + (n - 1)) / n * n;
        base = (void*)addr;
    }

    /* Unmap [MPTR...BASE] */
    {
        uint8_t* start = (uint8_t*)mptr;
        uint8_t* end = (uint8_t*)base;

        if (start != end && munmap(start, end - start) != 0)
            goto done;
    }

    /* Unmap [BASE+SIZE...MPTR+SIZE*2] */
    {
        uint8_t* start = (uint8_t*)base + enclaveSize;
        uint8_t* end = (uint8_t*)mptr + enclaveSize * 2;

        if (start != end && munmap(start, end - start) != 0)
            goto done;
    }

    result = base;

done:

    /* On failure, unmap initially allocated region.
     * Linux will handle already unmapped regions within this original range */
    if (!result && mptr != MAP_FAILED)
        munmap(mptr, enclaveSize * 2);

    return result;

#elif defined(_WIN32)

    /* Allocate enclave memory for simulated mode only */

    void* result = NULL;
    void* base = NULL;
    void* mptr = NULL;

    /* Allocate virtual memory for this enclave */
    if (!(mptr = VirtualAlloc(
              NULL,
              enclaveSize * 2,
              MEM_COMMIT | MEM_RESERVE,
              PAGE_EXECUTE_READWRITE)))
    {
        goto done;
    }

    /* Align BASE on a boundary of SIZE */
    {
        uint64_t n = enclaveSize;
        uint64_t addr = ((uint64_t)mptr + (n - 1)) / n * n;
        base = (void*)addr;
    }

    /* Release [MPTR...BASE] */
    {
        uint8_t* start = (uint8_t*)mptr;
        uint8_t* end = (uint8_t*)base;

        if (start != end && !VirtualFree(start, end - start, MEM_DECOMMIT))
            goto done;
    }

    /* Release [BASE+SIZE...MPTR+SIZE*2] */
    {
        uint8_t* start = (uint8_t*)base + enclaveSize;
        uint8_t* end = (uint8_t*)mptr + enclaveSize * 2;

        if (start != end && !VirtualFree(start, end - start, MEM_DECOMMIT))
            goto done;
    }

    result = base;

done:

    /* On failure, release the initial allocation. */
    if (!result && mptr)
        VirtualFree(mptr, 0, MEM_RELEASE);

    return result;

#endif /* defined(_WIN32) */
}

OE_Result OE_SGXInitializeLoadContext(
    OE_SGXLoadContext* context,
    OE_SGXLoadType type,
    uint32_t attributes)
{
    OE_Result result = OE_UNEXPECTED;

    if (context)
        memset(context, 0, sizeof(OE_SGXLoadContext));

    if (!context || type == OE_SGX_LOADTYPE_UNDEFINED)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set attributes before checking context properties */
    context->type = type;
    context->attributes = attributes;
    context->dev = OE_SGX_NO_DEVICE_HANDLE;
#if defined(__linux__)
    if (type != OE_SGX_LOADTYPE_MEASURE && !OE_SGXLoadIsSimulation(context))
    {
        context->dev = open("/dev/isgx", O_RDWR);
        if (context->dev == OE_SGX_NO_DEVICE_HANDLE)
            OE_THROW(OE_FAILURE);
    }
#endif

    context->state = OE_SGX_LOADSTATE_INITIALIZED;
    result = OE_OK;

OE_CATCH:
    return result;
}

void OE_SGXCleanupLoadContext(OE_SGXLoadContext* context)
{
#if defined(__linux__)
    if (context && context->dev != OE_SGX_NO_DEVICE_HANDLE)
        close(context->dev);
#endif
    /* Clear all fields, this also sets state to undefined */
    memset(context, 0, sizeof(OE_SGXLoadContext));
}

OE_Result OE_SGXCreateEnclave(
    OE_SGXLoadContext* context,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr)
{
    OE_Result result = OE_UNEXPECTED;
    void* base = NULL;
    SGX_Secs* secs = NULL;

    if (enclaveAddr)
        *enclaveAddr = 0;

    if (!context || !enclaveSize || !enclaveAddr)
        OE_THROW(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOADSTATE_INITIALIZED)
        OE_THROW(OE_INVALID_PARAMETER);

    /* SIZE must be a power of two */
    if (enclaveSize != OE_RoundU64ToPow2(enclaveSize))
        OE_THROW(OE_INVALID_PARAMETER);

#if defined(_WIN32)
    if (OE_SGXLoadIsSimulation(context))
#endif
    {
        /* Allocation memory-mapped region */
        if (!(base = _AllocateEnclaveMemory(enclaveSize, context->dev)))
            OE_THROW(OE_OUT_OF_MEMORY);
    }

    /* Create SECS structure */
    if (!(secs = _NewSecs(
              (uint64_t)base, enclaveSize, OE_SGXLoadIsDebug(context))))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Measure this operation */
    OE_TRY(OE_SGXMeasureCreateEnclave(&context->hashContext, secs));

    if (context->type == OE_SGX_LOADTYPE_MEASURE)
    {
        /* Create a phony address */
        base = (void*)0xffffffff00000000;
    }
    else if (OE_SGXLoadIsSimulation(context))
    {
        /* Simulate enclave creation */
        context->sim.addr = (void*)secs->base;
        context->sim.size = secs->size;
    }
    else
    {
#if defined(__linux__)

        /* Ask the Linux SGX driver to create the encalve */
        if (SGX_IoctlEnclaveCreate(context->dev, secs) != 0)
            OE_THROW(OE_IOCTL_FAILED);

#elif defined(_WIN32)

        /* Ask OS to create the enclave */
        DWORD enclaveError;
        void* base = CreateEnclave(
            GetCurrentProcess(),
            NULL, /* Let OS choose the enclave base address */
            secs->size,
            secs->size,
            ENCLAVE_TYPE_SGX,
            (const void*)secs,
            sizeof(ENCLAVE_CREATE_INFO_SGX),
            &enclaveError);

        if (!base)
            OE_THROW(OE_PLATFORM_ERROR);

        secs->base = (uint64_t)base;

#endif
    }

    *enclaveAddr = base ? (uint64_t)base : secs->base;
    context->state = OE_SGX_LOADSTATE_ENCLAVE_CREATED;
    result = OE_OK;

OE_CATCH:

    if (secs)
        OE_MemalignFree(secs);

    return result;
}

OE_Result OE_SGXLoadEnclaveData(
    OE_SGXLoadContext* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    OE_Result result = OE_UNEXPECTED;

    if (!context || !base || !addr || !src || !flags)
        OE_THROW(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOADSTATE_ENCLAVE_CREATED)
        OE_THROW(OE_INVALID_PARAMETER);

    /* ADDR must be page aligned */
    if (addr % OE_PAGE_SIZE)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    OE_TRY(
        OE_SGXMeasureLoadEnclaveData(
            &context->hashContext, base, addr, src, flags, extend));

    if (context->type == OE_SGX_LOADTYPE_MEASURE)
    {
        /* EADD has no further action in measurement mode */
        result = OE_OK;
        goto OE_CATCH;
    }
    else if (OE_SGXLoadIsSimulation(context))
    {
        /* Simulate enclave add page */
        /* Verify that page is within enclave boundaries */
        if ((void*)addr < context->sim.addr ||
            (uint8_t*)addr >
                (uint8_t*)context->sim.addr + context->sim.size - OE_PAGE_SIZE)
        {
            OE_THROW(OE_FAILURE);
        }

        /* Copy page contents onto memory-mapped region */
        memcpy((uint8_t*)addr, (uint8_t*)src, OE_PAGE_SIZE);

        /* Set page access permissions */
        {
            uint32_t prot = _MakeMemoryProtectParam(flags, true /*simulate*/);

#if defined(__linux__)
            if (mprotect((void*)addr, OE_PAGE_SIZE, prot) != 0)
                OE_THROW(OE_FAILURE);
#elif defined(_WIN32)
            DWORD old;
            if (!VirtualProtect((LPVOID)addr, OE_PAGE_SIZE, prot, &old))
                OE_THROW(OE_FAILURE);
#endif
        }
    }
    else
    {
#if defined(__linux__)

        /* Ask the Linux SGX driver to add a page to the enclave */
        if (SGX_IoctlEnclaveAddPage(context->dev, addr, src, flags, extend) !=
            0)
            OE_THROW(OE_IOCTL_FAILED);

#elif defined(_WIN32)

        /* Ask the OS to add a page to the encalve */
        SIZE_T num_bytes = 0;
        DWORD enclaveError;

        DWORD protect = _MakeMemoryProtectParam(flags, false /*not simulate*/);
        if (!extend)
            protect |= PAGE_ENCLAVE_UNVALIDATED;

        if (!LoadEnclaveData(
                GetCurrentProcess(),
                (LPVOID)addr,
                (LPCVOID)src,
                OE_PAGE_SIZE,
                protect,
                NULL,
                0,
                &num_bytes,
                &enclaveError))
        {
            OE_THROW(OE_PLATFORM_ERROR);
        }

#endif
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

OE_Result OE_SGXInitializeEnclave(
    OE_SGXLoadContext* context,
    uint64_t addr,
    uint64_t sigstruct,
    OE_SHA256* mrenclave)
{
    OE_Result result = OE_UNEXPECTED;
    AESM* aesm = NULL;

    if (mrenclave)
        memset(mrenclave, 0, sizeof(OE_SHA256));

    if (!context || !addr || !sigstruct || !mrenclave)
        OE_THROW(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOADSTATE_ENCLAVE_CREATED)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    OE_TRY(OE_SGXMeasureInitializeEnclave(&context->hashContext, mrenclave));

    /* EINIT has no further action in measurement/simulation mode */
    if (context->type == OE_SGX_LOADTYPE_CREATE &&
        !OE_SGXLoadIsSimulation(context))
    {
        /* Get a launch token from the AESM service */
        SGX_SigStruct* sgxSigStruct = (SGX_SigStruct*)sigstruct;

        SGX_LaunchToken launchToken;
        memset(&launchToken, 0, sizeof(SGX_LaunchToken));

        SGX_Attributes attributes;
        memset(&attributes, 0, sizeof(SGX_Attributes));
        attributes.flags = SGX_FLAGS_MODE64BIT;
        if (OE_SGXLoadIsDebug(context))
            attributes.flags |= SGX_FLAGS_DEBUG;
        attributes.xfrm = 0x7;

        if (!(aesm = AESMConnect()))
            OE_THROW(OE_FAILURE);

        OE_TRY(
            AESMGetLaunchToken(
                aesm,
                sgxSigStruct->enclavehash,
                sgxSigStruct->modulus,
                &attributes,
                &launchToken));

        OE_STATIC_ASSERT(sizeof(*sgxSigStruct) == sizeof(SGX_SigStruct));
        OE_STATIC_ASSERT(sizeof(SGX_LaunchToken) == sizeof(launchToken));

#if defined(__linux__)

        /* Ask the Linux SGX driver to initialize the enclave */
        if (SGX_IoctlEnclaveInit(
                context->dev, addr, sigstruct, (uint64_t)&launchToken) != 0)
            OE_THROW(OE_IOCTL_FAILED);

#elif defined(_WIN32)

        OE_STATIC_ASSERT(
            OE_FIELD_SIZE(ENCLAVE_INIT_INFO_SGX, SigStruct) ==
            sizeof(*sgxSigStruct));
        OE_STATIC_ASSERT(
            OE_FIELD_SIZE(ENCLAVE_INIT_INFO_SGX, EInitToken) <=
            sizeof(launchToken));

        /* Ask the OS to initialize the enclave */
        DWORD enclaveError;
        ENCLAVE_INIT_INFO_SGX info;

        memset(&info, 0, sizeof(info));
        memcpy(&info.SigStruct, (void*)sgxSigStruct, sizeof(info.SigStruct));
        memcpy(&info.EInitToken, (void*)&launchToken, sizeof(info.EInitToken));

        if (!InitializeEnclave(
                GetCurrentProcess(),
                (LPVOID)addr,
                &info,
                sizeof(info),
                &enclaveError))
        {
            OE_THROW(OE_PLATFORM_ERROR);
        }
#endif
    }

    context->state = OE_SGX_LOADSTATE_ENCLAVE_INITIALIZED;
    result = OE_OK;

OE_CATCH:

    if (aesm)
        AESMDisconnect(aesm);

    return result;
}
