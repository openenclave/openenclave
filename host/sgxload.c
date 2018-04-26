// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include "sgxload.h"
#if defined(OE_USE_LIBSGX)
#include <sgx_enclave_common.h>
#endif

#if defined(__linux__)
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "linux/sgxioctl.h"
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <openenclave/bits/aesm.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxcreate.h>
#include <openenclave/bits/sgxsign.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include "memalign.h"
#include "sgxmeasure.h"
#include "signkey.h"

static uint32_t _MakeMemoryProtectParam(uint64_t inflags, bool simulate)
{
    uint32_t outflags = 0;

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
#if defined(OE_USE_LIBSGX)
            /* libsgx is only used when not in simulation mode */
            outflags = ENCLAVE_PAGE_THREAD_CONTROL | ENCLAVE_PAGE_READ |
                       ENCLAVE_PAGE_WRITE;
#elif defined(__linux__)
            outflags = PROT_NONE;
#elif defined(_WIN32)
            outflags = PAGE_ENCLAVE_THREAD_CONTROL | PAGE_READWRITE;
#endif
        }
    }
    else if (inflags & SGX_SECINFO_REG)
    {
#if defined(OE_USE_LIBSGX)
        if (!simulate)
        {
            /* libsgx is only used when not in simulation mode */
            if (inflags & SGX_SECINFO_R)
                outflags |= ENCLAVE_PAGE_READ;

            if (inflags & SGX_SECINFO_W)
                outflags |= ENCLAVE_PAGE_WRITE;

            if (inflags & SGX_SECINFO_X)
                outflags |= ENCLAVE_PAGE_EXECUTE;
        }
        else
        {
/* simulation mode falls back to OS memory protection settings */
#endif
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
#if defined(OE_USE_LIBSGX)
        }
#endif
    }

    return outflags;
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

static OE_Result _GetSigStruct(
    const OE_SGXEnclaveProperties* properties,
    const OE_SHA256* mrenclave,
    SGX_SigStruct* sigstruct)
{
    OE_Result result = OE_UNEXPECTED;

    memset(sigstruct, 0, sizeof(SGX_SigStruct));

    /* If sigstruct doesn't have expected header, treat enclave as unsigned */
    if (memcmp(
            ((SGX_SigStruct*)properties->sigstruct)->header,
            SGX_SIGSTRUCT_HEADER,
            sizeof(SGX_SIGSTRUCT_HEADER)) != 0)
    {
        /* Only debug-sign unsigned enclaves in debug mode, fail otherwise */
        if (!(properties->config.attributes & SGX_FLAGS_DEBUG))
            OE_RAISE(OE_FAILURE);

        /* Perform debug-signing with well-known debug-signing key */
        OE_CHECK(
            OE_SGXSignEnclave(
                mrenclave,
                properties->config.attributes,
                properties->config.productID,
                properties->config.securityVersion,
                OE_DEBUG_SIGN_KEY,
                OE_DEBUG_SIGN_KEY_SIZE,
                sigstruct));
    }
    else
    {
        /* Otherwise, treat enclave as signed and use its sigstruct */
        memcpy(sigstruct, properties->sigstruct, sizeof(SGX_SigStruct));
    }

    result = OE_OK;

done:

    return result;
}

/* obtaining a launch token is only necessary when not using libsgx */
#if !defined(OE_USE_LIBSGX)
static OE_Result _GetLaunchToken(
    const OE_SGXEnclaveProperties* properties,
    SGX_SigStruct* sigstruct,
    SGX_LaunchToken* launchToken)
{
    OE_Result result = OE_UNEXPECTED;
    AESM* aesm = NULL;

    memset(launchToken, 0, sizeof(SGX_LaunchToken));

    /* Initialize the SGX attributes */
    SGX_Attributes attributes = {0};
    attributes.flags = properties->config.attributes;
    attributes.xfrm = SGX_ATTRIBUTES_DEFAULT_XFRM;

    /* Obtain a launch token from the AESM service */
    if (!(aesm = AESMConnect()))
        OE_RAISE(OE_FAILURE);

    OE_CHECK(
        AESMGetLaunchToken(
            aesm,
            sigstruct->enclavehash,
            sigstruct->modulus,
            &attributes,
            launchToken));

    result = OE_OK;

done:

    if (aesm)
        AESMDisconnect(aesm);

    return result;
}
#endif

OE_Result OE_SGXInitializeLoadContext(
    OE_SGXLoadContext* context,
    OE_SGXLoadType type,
    uint32_t attributes)
{
    OE_Result result = OE_UNEXPECTED;

    if (context)
        memset(context, 0, sizeof(OE_SGXLoadContext));

    if (!context || type == OE_SGX_LOAD_TYPE_UNDEFINED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Set attributes before checking context properties */
    context->type = type;
    context->attributes = attributes;
    context->dev = OE_SGX_NO_DEVICE_HANDLE;
#if !defined(OE_USE_LIBSGX) && defined(__linux__)
    if (type != OE_SGX_LOAD_TYPE_MEASURE && !OE_SGXLoadIsSimulation(context))
    {
        context->dev = open("/dev/isgx", O_RDWR);
        if (context->dev == OE_SGX_NO_DEVICE_HANDLE)
            OE_RAISE(OE_FAILURE);
    }
#endif

    context->state = OE_SGX_LOAD_STATE_INITIALIZED;
    result = OE_OK;

done:
    return result;
}

void OE_SGXCleanupLoadContext(OE_SGXLoadContext* context)
{
#if !defined(OE_USE_LIBSGX) && defined(__linux__)
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
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOAD_STATE_INITIALIZED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* SIZE must be a power of two */
    if (enclaveSize != OE_RoundU64ToPow2(enclaveSize))
        OE_RAISE(OE_INVALID_PARAMETER);

#if defined(OE_USE_LIBSGX) || defined(_WIN32)
    if (OE_SGXLoadIsSimulation(context))
#endif
    {
        /* Allocation memory-mapped region */
        if (!(base = _AllocateEnclaveMemory(enclaveSize, context->dev)))
            OE_RAISE(OE_OUT_OF_MEMORY);
    }

    /* Create SECS structure */
    if (!(secs = _NewSecs(
              (uint64_t)base, enclaveSize, OE_SGXLoadIsDebug(context))))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Measure this operation */
    OE_CHECK(OE_SGXMeasureCreateEnclave(&context->hashContext, secs));

    if (context->type == OE_SGX_LOAD_TYPE_MEASURE)
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
#if defined(OE_USE_LIBSGX)

        uint32_t enclaveError;
        void* base = enclave_create(
            NULL, /* Let OS choose the enclave base address */
            secs->size,
            secs->size,
            ENCLAVE_TYPE_SGX1,
            (const void*)secs,
            sizeof(SGX_Secs),
            &enclaveError);

        if (!base)
            OE_RAISE(OE_PLATFORM_ERROR);

        secs->base = (uint64_t)base;

#elif defined(__linux__)

        /* Ask the Linux SGX driver to create the encalve */
        if (SGX_IoctlEnclaveCreate(context->dev, secs) != 0)
            OE_RAISE(OE_IOCTL_FAILED);

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
            OE_RAISE(OE_PLATFORM_ERROR);

        secs->base = (uint64_t)base;

#endif
    }

    *enclaveAddr = base ? (uint64_t)base : secs->base;
    context->state = OE_SGX_LOAD_STATE_ENCLAVE_CREATED;
    result = OE_OK;

done:

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
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOAD_STATE_ENCLAVE_CREATED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* ADDR must be page aligned */
    if (addr % OE_PAGE_SIZE)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Measure this operation */
    OE_CHECK(
        OE_SGXMeasureLoadEnclaveData(
            &context->hashContext, base, addr, src, flags, extend));

    if (context->type == OE_SGX_LOAD_TYPE_MEASURE)
    {
        /* EADD has no further action in measurement mode */
        result = OE_OK;
        goto done;
    }
    else if (OE_SGXLoadIsSimulation(context))
    {
        /* Simulate enclave add page */
        /* Verify that page is within enclave boundaries */
        if ((void*)addr < context->sim.addr ||
            (uint8_t*)addr >
                (uint8_t*)context->sim.addr + context->sim.size - OE_PAGE_SIZE)
        {
            OE_RAISE(OE_FAILURE);
        }

        /* Copy page contents onto memory-mapped region */
        memcpy((uint8_t*)addr, (uint8_t*)src, OE_PAGE_SIZE);

        /* Set page access permissions */
        {
            uint32_t prot = _MakeMemoryProtectParam(flags, true /*simulate*/);

#if defined(__linux__)
            if (mprotect((void*)addr, OE_PAGE_SIZE, prot) != 0)
                OE_RAISE(OE_FAILURE);
#elif defined(_WIN32)
            DWORD old;
            if (!VirtualProtect((LPVOID)addr, OE_PAGE_SIZE, prot, &old))
                OE_RAISE(OE_FAILURE);
#endif
        }
    }
    else
    {
#if defined(OE_USE_LIBSGX)

        uint32_t protect =
            _MakeMemoryProtectParam(flags, false /*not simulate*/);
        if (!extend)
            protect |= ENCLAVE_PAGE_UNVALIDATED;

        uint32_t enclaveError;
        if (enclave_load_data(
                (void*)addr,
                OE_PAGE_SIZE,
                (const void*)src,
                protect,
                &enclaveError) != OE_PAGE_SIZE)
        {
            OE_RAISE(OE_PLATFORM_ERROR);
        }

#elif defined(__linux__)

        /* Ask the Linux SGX driver to add a page to the enclave */
        if (SGX_IoctlEnclaveAddPage(context->dev, addr, src, flags, extend) !=
            0)
            OE_RAISE(OE_IOCTL_FAILED);

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
            OE_RAISE(OE_PLATFORM_ERROR);
        }

#endif
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_SGXInitializeEnclave(
    OE_SGXLoadContext* context,
    uint64_t addr,
    const OE_SGXEnclaveProperties* properties,
    OE_SHA256* mrenclave)
{
    OE_Result result = OE_UNEXPECTED;

    if (mrenclave)
        memset(mrenclave, 0, sizeof(OE_SHA256));

    if (!context || !addr || !properties || !mrenclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (context->state != OE_SGX_LOAD_STATE_ENCLAVE_CREATED)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Measure this operation */
    OE_CHECK(OE_SGXMeasureInitializeEnclave(&context->hashContext, mrenclave));

    /* EINIT has no further action in measurement/simulation mode */
    if (context->type == OE_SGX_LOAD_TYPE_CREATE &&
        !OE_SGXLoadIsSimulation(context))
    {
        /* Get a debug sigstruct for MRENCLAVE if necessary */
        SGX_SigStruct sigstruct;
        OE_CHECK(_GetSigStruct(properties, mrenclave, &sigstruct));

#if defined(OE_USE_LIBSGX)

        uint32_t enclaveError = 0;
        if (!enclave_initialize(
                (void*)addr,
                (const void*)&sigstruct,
                sizeof(SGX_SigStruct),
                &enclaveError))
            OE_RAISE(OE_PLATFORM_ERROR);
        if (enclaveError != 0)
            OE_RAISE(OE_PLATFORM_ERROR);
#else
        /* If not using libsgx, get a launch token from the AESM service */
        SGX_LaunchToken launchToken;
        OE_CHECK(_GetLaunchToken(properties, &sigstruct, &launchToken));

#if defined(__linux__)

        /* Ask the Linux SGX driver to initialize the enclave */
        if (SGX_IoctlEnclaveInit(
                context->dev,
                addr,
                (uint64_t)&sigstruct,
                (uint64_t)&launchToken) != 0)
            OE_RAISE(OE_IOCTL_FAILED);

#elif defined(_WIN32)

        OE_STATIC_ASSERT(
            OE_FIELD_SIZE(ENCLAVE_INIT_INFO_SGX, SigStruct) ==
            sizeof(sigstruct));
        OE_STATIC_ASSERT(
            OE_FIELD_SIZE(ENCLAVE_INIT_INFO_SGX, EInitToken) <=
            sizeof(launchToken));

        /* Ask the OS to initialize the enclave */
        DWORD enclaveError;
        ENCLAVE_INIT_INFO_SGX info;

        memset(&info, 0, sizeof(info));
        memcpy(&info.SigStruct, (void*)&sigstruct, sizeof(info.SigStruct));
        memcpy(&info.EInitToken, (void*)&launchToken, sizeof(info.EInitToken));

        if (!InitializeEnclave(
                GetCurrentProcess(),
                (LPVOID)addr,
                &info,
                sizeof(info),
                &enclaveError))
        {
            OE_RAISE(OE_PLATFORM_ERROR);
        }
#endif
#endif
    }

    context->state = OE_SGX_LOAD_STATE_ENCLAVE_INITIALIZED;
    result = OE_OK;

done:

    return result;
}
