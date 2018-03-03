// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <openenclave/bits/build.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include "memalign.h"

/*
**==============================================================================
**
** Definition of Self struct (extends OE_SGXDevice)
**
**==============================================================================
*/

typedef struct _Self /* extends OE_SGXDevice */
{
    OE_SGXDevice base;
    unsigned int magic;
    int fd;
    OE_SGXDevice* measurer;

    /* Simulate mode */
    bool simulate;

    /* Simulate mode fields (used when simulate == true) */
    struct _Simulate
    {
        /* Base address of enclave */
        void* addr;

        /* Size of enclave in bytes */
        size_t size;
    } sim;

    int (*ioctl)(struct _Self* dev, unsigned long request, void* param);
} Self;

static int _Ok(const Self* self)
{
    return self && self->magic == SGX_DRIVER_MAGIC;
}

/*
**==============================================================================
**
** Implementation of Intel SGX IOCTL interface (real and simulated)
**
**     _Ioctl() => _IoctlReal() or _IoctlSimulate()
**
**==============================================================================
*/

#define SGX_MAGIC 0xA4
#define SGX_IOC_ENCLAVE_CREATE _IOW(SGX_MAGIC, 0x00, SGXECreateParam)
#define SGX_IOC_ENCLAVE_ADD_PAGE _IOW(SGX_MAGIC, 0x01, SGXEAddParam)
#define SGX_IOC_ENCLAVE_INIT _IOW(SGX_MAGIC, 0x02, SGXEinitParam)

OE_PACK_BEGIN
typedef struct __SGXECreateParam
{
    uint64_t src;
} SGXECreateParam;
OE_PACK_END

typedef struct _SecInfo
{
    uint64_t flags;
    uint64_t reserved[7];
} OE_ALIGNED(128) SecInfo;

static uint32_t _MakeMemoryProtectParam(const SecInfo* secinfo, bool simulate)
{
#if defined(__linux__)

    uint32_t flags = 0;

    if (secinfo->flags & SGX_SECINFO_TCS)
    {
        if (simulate)
        {
            /* TCS can be read and written in simulation mode */
            flags = PROT_READ | PROT_WRITE;
        }
        else
        {
            flags = PROT_NONE;
        }
    }
    else if (secinfo->flags & SGX_SECINFO_REG)
    {
        if (secinfo->flags & SGX_SECINFO_R)
            flags |= PROT_READ;

        if (secinfo->flags & SGX_SECINFO_W)
            flags |= PROT_WRITE;

        if (secinfo->flags & SGX_SECINFO_X)
            flags |= PROT_WRITE;
    }

    return flags;

#elif defined(_WIN32)

    if (secinfo->flags & SGX_SECINFO_TCS)
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

    if (secinfo->flags & SGX_SECINFO_REG)
    {
        if ((secinfo->flags & SGX_SECINFO_X) &&
            (secinfo->flags & SGX_SECINFO_R) &&
            (secinfo->flags & SGX_SECINFO_W))
        {
            return PAGE_EXECUTE_READWRITE;
        }

        if ((secinfo->flags & SGX_SECINFO_X) &&
            (secinfo->flags & SGX_SECINFO_R))
        {
            return PAGE_EXECUTE_READ;
        }

        if ((secinfo->flags & SGX_SECINFO_X))
            return PAGE_EXECUTE;

        if ((secinfo->flags & SGX_SECINFO_R) &&
            (secinfo->flags & SGX_SECINFO_W))
        {
            return PAGE_READWRITE;
        }

        if ((secinfo->flags & SGX_SECINFO_R))
            return PAGE_READONLY;
    }

    return PAGE_NOACCESS;

#endif
}

OE_PACK_BEGIN
typedef struct __SGXEAddParam
{
    uint64_t addr;    /* enclaves address to copy to */
    uint64_t src;     /* user address to copy from */
    uint64_t secinfo; /* section information about this page */
    uint16_t mrmask;  /* 0xffff if extend (measurement) will be performed */
} SGXEAddParam;
OE_PACK_END

OE_PACK_BEGIN
typedef struct __SGXEinitParam
{
    uint64_t addr;
    uint64_t sigstruct;
    uint64_t einittoken;
} SGXEinitParam;
OE_PACK_END

static SGX_Secs* _NewSecs(uint64_t base, uint64_t size)
{
    SGX_Secs* secs = NULL;

    if (!(secs = (SGX_Secs*)OE_Memalign(OE_PAGE_SIZE, sizeof(SGX_Secs))))
        return NULL;

    memset(secs, 0, sizeof(SGX_Secs));
    secs->size = size;
    secs->base = base;

    /* ATTN: debug is hardcoded here; pass this in as parameter */
    secs->flags = SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT;

    /* what the driver sees with SGX SDK */
    secs->xfrm = SGX_ATTRIBUTES_DEFAULT_XFRM; 

    /* COMMENT1: ssaframesize hardcoded to one for now */
    secs->ssaframesize = 1;

    /* secs->flags |= SGX_FLAGS_EINITTOKEN_KEY; */
    /* secs->flags |= SGX_FLAGS_PROVISION_KEY; */

    return secs;
}

static int _IoctlSimulate(Self* self, unsigned long request, void* param)
{
    switch (request)
    {
        case SGX_IOC_ENCLAVE_CREATE:
        {
            const SGXECreateParam* p;
            const SGX_Secs* secs;

            if (!(p = (const SGXECreateParam*)param))
                return -1;

            if (!(secs = (const SGX_Secs*)p->src))
                return -1;

            if (!secs->base || !secs->size)
                return -1;

            self->sim.addr = (void*)secs->base;
            self->sim.size = secs->size;

            return 0;
        }
        case SGX_IOC_ENCLAVE_ADD_PAGE:
        {
            const SGXEAddParam* p;
            void* addr;
            const void* src;
            const SecInfo* secinfo;

            if (!(p = (const SGXEAddParam*)param))
                return -1;

            if (!(addr = (void*)p->addr))
                return -1;

            if (!(src = (const void*)p->src))
                return -1;

            if (!(secinfo = (const SecInfo*)p->secinfo))
                return -1;

            /* Verify that page is within enclave boundaries */
            if (addr < self->sim.addr ||
                (uint8_t*)addr >
                    (uint8_t*)self->sim.addr + self->sim.size - OE_PAGE_SIZE)
            {
                return -1;
            }

            /* Copy page contents onto memory-mapped region */
            memcpy(addr, src, OE_PAGE_SIZE);

            /* Set page access permissions */
            {
                uint32_t prot = _MakeMemoryProtectParam(secinfo, true);

#if defined(__linux__)
                if (mprotect(addr, OE_PAGE_SIZE, prot) != 0)
                    return -1;
#elif defined(_WIN32)
                DWORD old;
                if (!VirtualProtect(addr, OE_PAGE_SIZE, prot, &old))
                    return -1;
#endif
            }

            return 0;
        }
        case SGX_IOC_ENCLAVE_INIT:
        {
            /* Nothing to be done here for simulation */
            return 0;
        }
        default:
        {
            return -1;
        }
    }

    /* Unreachable */
    return 0;
}

static int _IoctlReal(Self* self, unsigned long request, void* param)
{
#if defined(__linux__)

    return ioctl(self->fd, request, param);

#elif defined(_WIN32)

    switch (request)
    {
        case SGX_IOC_ENCLAVE_CREATE:
        {
            const SGXECreateParam* p;
            SGX_Secs* secs;
            DWORD enclaveError;

            if (!(p = (const SGXECreateParam*)param))
                return -1;

            if (!(secs = (SGX_Secs*)p->src))
                return -1;

            if (!secs->size)
                return -1;

            /* Ask OS to create the enclave */
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
                return -1;

            secs->base = (uint64_t)base;

            return 0;
        }
        case SGX_IOC_ENCLAVE_ADD_PAGE:
        {
            const SGXEAddParam* p;
            void* addr;
            const void* src;
            const SecInfo* secinfo;

            if (!(p = (const SGXEAddParam*)param))
                return -1;

            if (!(addr = (void*)p->addr))
                return -1;

            if (!(src = (const void*)p->src))
                return -1;

            if (!(secinfo = (const SecInfo*)p->secinfo))
                return -1;

            SIZE_T num_bytes = 0;
            DWORD enclaveError;

            DWORD protect = _MakeMemoryProtectParam(secinfo, false);

            if (p->mrmask != 0xffff)
            {
                /* Do not extend (measure) this page */
                protect |= PAGE_ENCLAVE_UNVALIDATED;
            }

            if (!LoadEnclaveData(
                    GetCurrentProcess(),
                    addr,
                    src,
                    OE_PAGE_SIZE,
                    protect,
                    NULL,
                    0,
                    &num_bytes,
                    &enclaveError))
            {
                return -1;
            }

            return 0;
        }
        case SGX_IOC_ENCLAVE_INIT:
        {
            DWORD enclaveError;
            const SGXEinitParam* p = (const SGXEinitParam*)param;
            ENCLAVE_INIT_INFO_SGX info;

            memset(&info, 0, sizeof(info));
            memcpy(
                &info.SigStruct, (void*)p->sigstruct, sizeof(info.SigStruct));
            memcpy(
                &info.EInitToken,
                (void*)p->einittoken,
                sizeof(info.EInitToken));

            if (!InitializeEnclave(
                    GetCurrentProcess(),
                    (void*)p->addr,
                    &info,
                    sizeof(info),
                    &enclaveError))
            {
                return -1;
            }

            return 0;
        }
        default:
        {
            return -1;
        }
    }

    /* Unreachable */
    return -1;

#endif
}

static int _Ioctl(Self* dev, unsigned long request, void* param)
{
    if (dev->simulate)
        return _IoctlSimulate(dev, request, param);
    else
        return _IoctlReal(dev, request, param);
}

static void* _AllocateEnclaveMemory(uint64_t enclaveSize, int fd)
{
/*
** Resulting memory layout:
**
**    [............xxxxxxxxxxxxxxxxxxxxxxxx...............]
**     ^           ^                       ^              ^
**    MPTR        BASE                 BASE+SIZE      MPTR+SIZE*2
**
**    [MPTR...BASE]                 - unused
**    [BASE...BASE+SIZE]            - used
**    [BASE+SIZE...MPTR+SIZE*2]     - unused
**
*/

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

    return result;

#endif /* defined(_WIN32) */
}

/*
**==============================================================================
**
** Definition of the following OE_SGXDevice methods:
**
**     OE_SGXDevice.ecreate()
**     OE_SGXDevice.eadd()
**     OE_SGXDevice.einit()
**     OE_SGXDevice.gethash()
**     OE_SGXDevice.close()
**     OE_SGXDevice.getmagic()
**
**==============================================================================
*/

static OE_Result _ECreateProc(
    OE_SGXDevice* dev,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr)
{
    Self* self = (Self*)dev;
    OE_Result result = OE_UNEXPECTED;
    void* base = NULL;
    SGX_Secs* secs = NULL;

    if (enclaveAddr)
        *enclaveAddr = 0;

    if (!_Ok(self) || !enclaveSize || !enclaveAddr)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    if (self->measurer->ecreate(self->measurer, enclaveSize, enclaveAddr) !=
        OE_OK)
    {
        OE_THROW(OE_FAILURE);
    }

    /* SIZE must be a power of two */
    if (enclaveSize != OE_RoundU64ToPow2(enclaveSize))
        OE_THROW(OE_INVALID_PARAMETER);

#if defined(_WIN32)
    if (self->simulate)
#endif
    {
        /* Allocation memory-mapped region */
        if (!(base = _AllocateEnclaveMemory(enclaveSize, self->fd)))
            OE_THROW(OE_OUT_OF_MEMORY);
    }

    /* Create SECS structure */
    if (!(secs = _NewSecs((uint64_t)base, enclaveSize)))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Ask driver to perform ECREATE */
    {
        SGXECreateParam param;

        memset(&param, 0, sizeof(param));
        param.src = (unsigned long long)secs;

        if (_Ioctl(self, SGX_IOC_ENCLAVE_CREATE, &param) != 0)
            OE_THROW(OE_IOCTL_FAILED);
    }

    *enclaveAddr = base ? (uint64_t)base : secs->base;

    result = OE_OK;

OE_CATCH:

    if (secs)
        OE_MemalignFree(secs);

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
    Self* self = (Self*)dev;
    OE_Result result = OE_UNEXPECTED;

    if (!_Ok(self) || !base || !addr || !src || !flags)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    if (self->measurer->eadd(self->measurer, base, addr, src, flags, extend) !=
        OE_OK)
    {
        OE_THROW(OE_FAILURE);
    }

    /* ADDR must be page aligned */
    if (addr % OE_PAGE_SIZE)
        OE_THROW(OE_FAILURE);

    /* Ask driver to perform EADD */
    {
        SGXEAddParam param;
        SecInfo secinfo;

        memset(&secinfo, 0, sizeof(SecInfo));
        secinfo.flags = flags;

        memset(&param, 0, sizeof(param));
        param.addr = addr;
        param.src = src;
        param.secinfo = (uint64_t)&secinfo;

        /* Whether to perform EEXTEND on this page (or parts of it) */
        if (extend)
            param.mrmask = 0xffff;

        if (_Ioctl(self, SGX_IOC_ENCLAVE_ADD_PAGE, &param) != 0)
            OE_THROW(OE_IOCTL_FAILED);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

static OE_Result _EInitProc(
    OE_SGXDevice* dev,
    uint64_t addr,
    uint64_t sigstruct,
    uint64_t einittoken)
{
    Self* self = (Self*)dev;
    OE_Result result = OE_UNEXPECTED;

    if (!_Ok(self) || !addr || !sigstruct || !einittoken)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    if (self->measurer->einit(self->measurer, addr, sigstruct, einittoken) !=
        OE_OK)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Ask driver to perform EINIT */
    {
        SGXEinitParam param;

        memset(&param, 0, sizeof(param));
        param.addr = addr;
        param.sigstruct = sigstruct;
        param.einittoken = einittoken;

        if (_Ioctl(self, SGX_IOC_ENCLAVE_INIT, &param) != 0)
            OE_THROW(OE_IOCTL_FAILED);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

static OE_Result _GetHashProc(OE_SGXDevice* dev, OE_SHA256* hash)
{
    OE_Result result = OE_UNEXPECTED;
    Self* self = (Self*)dev;

    if (!_Ok(self))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Get the final measurement */
    if (self->measurer->gethash(self->measurer, hash) != OE_OK)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:
    return result;
}

static OE_Result _CloseProc(OE_SGXDevice* dev)
{
    OE_Result result = OE_UNEXPECTED;
    Self* self = (Self*)dev;

    if (!_Ok(self))
        OE_THROW(OE_INVALID_PARAMETER);

    self->measurer->close(self->measurer);

#if defined(__linux__)
    if (self->fd != -1)
        close(self->fd);
#endif

    result = OE_OK;

OE_CATCH:
    return result;
}

static uint32_t _GetMagic(const OE_SGXDevice* dev)
{
    Self* self = (Self*)dev;

    if (!_Ok(self))
        return 0;

    return self->magic;
}

OE_SGXDevice* __OE_OpenSGXDriver(bool simulate)
{
    OE_SGXDevice* result = NULL;
    Self* self;

    if (!(self = (Self*)calloc(1, sizeof(Self))))
        goto catch;

    self->fd = -1;

#if defined(__linux__)
    if (!simulate && (self->fd = open("/dev/isgx", O_RDWR)) == -1)
        goto catch;
#endif

    if (!(self->measurer = __OE_OpenSGXMeasurer()))
        goto catch;

    self->base.ecreate = _ECreateProc;
    self->base.eadd = _EAddProc;
    self->base.einit = _EInitProc;
    self->base.gethash = _GetHashProc;
    self->base.close = _CloseProc;
    self->base.getmagic = _GetMagic;
    self->magic = SGX_DRIVER_MAGIC;
    self->simulate = simulate;

    result = &self->base;

OE_CATCH:

    if (!result)
        free(self);

    return result;
}
