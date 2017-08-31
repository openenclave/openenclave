#define OE_TRACE_LEVEL 1
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <oeinternal/utils.h>
#include <oeinternal/build.h>
#include <oeinternal/sgxtypes.h>
#include "log.h"

#define SGX_MAGIC 0xA4

#define SGX_IOC_ENCLAVE_CREATE \
    _IOW(SGX_MAGIC, 0x00, SGXECreateParam)

#define SGX_IOC_ENCLAVE_ADD_PAGE \
    _IOW(SGX_MAGIC, 0x01, SGXEAddParam)

#define SGX_IOC_ENCLAVE_INIT \
    _IOW(SGX_MAGIC, 0x02, SGXEinitParam)

typedef struct _Simulate
{
    /* Base address of enclave */
    void* addr;

    /* Size of enclave in bytes */
    size_t size;
}
Simulate;

typedef struct _Self Self;

typedef struct _Self
{
    OE_SGXDevice base;
    unsigned int magic;
    int fd;
    OE_SGXDevice* measurer; 

    /* Simulate mode */
    bool simulate;

    /* Simulate mode fields (used when fd == -1) */
    Simulate sim;

    int (*ioctl)(struct _Self* dev, unsigned long request, void* param);
}
Self;

static int _Ok(const Self* self)
{
    return self && self->magic == SGX_DRIVER_MAGIC;
}

typedef struct __SGXECreateParam  
{
    uint64_t src;
}
OE_PACKED
SGXECreateParam;

typedef struct _SecInfo
{
    uint64_t flags;
    uint64_t reserved[7];
}
OE_ALIGNED(128)
SecInfo;

static uint8_t _MakeMProtectFlags(uint64_t secInfoFlags)
{
    uint8_t flags = 0;

    if (secInfoFlags & SGX_SECINFO_TCS)
    {
        /* TCS can be read and written in simulation mode */
        flags = PROT_READ | PROT_WRITE;
        goto done;
    }

    if (secInfoFlags & SGX_SECINFO_REG)
    {
        if (secInfoFlags & SGX_SECINFO_R)
            flags |= PROT_READ;

        if (secInfoFlags & SGX_SECINFO_W)
            flags |= PROT_WRITE;

        if (secInfoFlags & SGX_SECINFO_X)
            flags |= PROT_WRITE;
    }

done:
    return flags;
}

typedef struct __SGXEAddParam
{
    uint64_t addr;    /* enclaves address to copy to */
    uint64_t src;     /* user address to copy from */
    uint64_t secinfo; /* section information about this page */
    uint16_t mrmask;  /* 0xffff if extend (measurement) will be performed */
}
OE_PACKED
SGXEAddParam;

typedef struct __SGXEinitParam 
{
    uint64_t addr;
    uint64_t sigstruct;
    uint64_t einittoken;
} 
OE_PACKED
SGXEinitParam;

static SGX_Secs* _NewSecs(uint64_t base, uint64_t size)
{
    SGX_Secs* secs = NULL;
    extern void *memalign(size_t alignment, size_t size);

    if (!(secs = (SGX_Secs*)memalign(OE_PAGE_SIZE, sizeof(SGX_Secs))))
        return NULL;

    memset(secs, 0, sizeof(SGX_Secs));
    secs->size = size;
    secs->base = base;
    secs->flags = SGX_FLAGS_DEBUG | SGX_FLAGS_MODE64BIT;
    secs->xfrm = 0x07; /* what the driver sees with SGX SDK */
    /* COMMENT1: ssaframesize hardcoded to one for now */
    secs->ssaframesize = 1;
    /* secs->flags |= SGX_FLAGS_EINITTOKEN_KEY; */
    /* secs->flags |= SGX_FLAGS_PROVISION_KEY; */

    return secs;
}

static int _IoctlSimulate(
    Self* self,
    unsigned long request,
    void* param)
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
                addr > self->sim.addr + self->sim.size - OE_PAGE_SIZE)
            {
                return -1;
            }

            /* Copy page contents onto memory-mapped region */
            memcpy(addr, src, OE_PAGE_SIZE);

            /* Set page access permissions */
            {
                uint8_t flags = _MakeMProtectFlags(secinfo->flags);

                if (mprotect(addr, OE_PAGE_SIZE, flags) != 0)
                    return -1;
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

static int _Ioctl(
    Self* dev,
    unsigned long request,
    void* param)
{
    if (dev->fd == -1)
        return _IoctlSimulate(dev, request, param);
    else
        return ioctl(dev->fd, request, param);
}

static OE_Result _ECreateProc(
    OE_SGXDevice* dev,
    uint64_t enclaveSize,
    uint64_t* enclaveAddr)
{
    Self* self = (Self*)dev;
    OE_Result result = OE_UNEXPECTED;
    void* mptr = NULL;
    void* base = NULL;
    SGX_Secs* secs = NULL;

    if (enclaveAddr)
        *enclaveAddr = 0;

    if (!_Ok(self) || !enclaveSize || !enclaveAddr)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Measure this operation */
    if (self->measurer->ecreate(
        self->measurer, enclaveSize, enclaveAddr) != OE_OK)
    {
        OE_THROW(OE_FAILURE);
    }

    /* SIZE must be a power of two */
    if (enclaveSize != OE_RoundU64ToPow2(enclaveSize))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Map memory to share with "/dev/isgx" */
    {
        int mprot = PROT_READ | PROT_WRITE | PROT_EXEC;
        int mflags = MAP_SHARED;

        if (self->simulate)
            mflags |= MAP_ANONYMOUS;

        /* Allocate double so BASE can be aligned on SIZE boundary */
        mptr = mmap(NULL, enclaveSize * 2, mprot, mflags, self->fd, 0);

        if(mptr == MAP_FAILED)
            OE_THROW(OE_FAILURE);
    }

    /* Align BASE on a boundary of SIZE */
    {
        uint64_t n = enclaveSize;
        uint64_t addr = ((uint64_t)mptr + (n - 1)) / n * n;
        base = (void*)addr;
    }

    /*
    ** Resulting mmap() layout:
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

    /* Unmap [MPTR...BASE] */
    {
        uint8_t* start = (uint8_t*)mptr;
        uint8_t* end = (uint8_t*)base;

        if (start != end && munmap(start, end - start) != 0)
            OE_THROW(OE_FAILURE);
    }

    /* Unmap [BASE+SIZE...MPTR+SIZE*2] */
    {
        uint8_t* start = (uint8_t*)base + enclaveSize;
        uint8_t* end = (uint8_t*)mptr + enclaveSize * 2;

        if (start != end && munmap(start, end - start) != 0)
            OE_THROW(OE_FAILURE);
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

    *enclaveAddr = (uint64_t)base;

    result = OE_OK;

catch:

    if (secs)
        free(secs);

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
    if (self->measurer->eadd(
        self->measurer, base, addr, src, flags, extend) != OE_OK)
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

catch:

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
    if (self->measurer->einit(
        self->measurer, addr, sigstruct, einittoken) != OE_OK)
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

catch:

    return result;
}


static OE_Result _GetHashProc(
    OE_SGXDevice* dev,
    OE_SHA256* hash)
{
    OE_Result result = OE_UNEXPECTED;
    Self* self = (Self*)dev;

    if (!_Ok(self))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Get the final measurement */
    if (self->measurer->gethash(self->measurer, hash) != OE_OK)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

catch:
    return result;
}

static OE_Result _CloseProc(
    OE_SGXDevice* dev)
{
    OE_Result result = OE_UNEXPECTED;
    Self* self = (Self*)dev;

    if (!_Ok(self))
        OE_THROW(OE_INVALID_PARAMETER);

    self->measurer->close(self->measurer);

    if (self->fd != -1)
        close(self->fd);

    result = OE_OK;

catch:
    return result;
}

static uint32_t _GetMagic(
    const OE_SGXDevice* dev)
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

    if (simulate)
    {
        self->fd = -1;
    }
    else if ((self->fd = open("/dev/isgx", O_RDWR)) == -1)
    {
        goto catch;
    }

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

catch:

    if (!result)
        free(self);

    return result;
}
