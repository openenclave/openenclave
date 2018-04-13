// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "sgxioctl.h"
#include <openenclave/bits/sgxtypes.h>
#include <string.h>
#include <sys/ioctl.h>

/*
**==============================================================================
**
** Implementation of Intel SGX IOCTL interface
**
**==============================================================================
*/

#define SGX_MAGIC 0xA4
#define SGX_IOC_ENCLAVE_CREATE _IOW(SGX_MAGIC, 0x00, SGXECreateParam)
#define SGX_IOC_ENCLAVE_ADD_PAGE _IOW(SGX_MAGIC, 0x01, SGXEAddParam)
#define SGX_IOC_ENCLAVE_INIT _IOW(SGX_MAGIC, 0x02, SGXEInitParam)

OE_PACK_BEGIN
typedef struct __SGXECreateParam
{
    uint64_t secs;
} SGXECreateParam;
OE_PACK_END

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
typedef struct __SGXEInitParam
{
    uint64_t addr;
    uint64_t sigstruct;
    uint64_t einittoken;
} SGXEInitParam;
OE_PACK_END

int SGX_IoctlEnclaveCreate(int dev, SGX_Secs* secs)
{
    SGXECreateParam param;

    if (dev == -1 || !secs)
        return -1;

    memset(&param, 0, sizeof(param));
    param.secs = (unsigned long long)secs;

    return ioctl(dev, SGX_IOC_ENCLAVE_CREATE, &param);
}

int SGX_IoctlEnclaveAddPage(
    int dev,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    SGXEAddParam param;
    SGX_SecInfo secinfo;

    if (dev == -1 || !addr || !src || !flags)
        return -1;

    memset(&secinfo, 0, sizeof(SGX_SecInfo));
    secinfo.flags = flags;

    memset(&param, 0, sizeof(param));
    param.addr = addr;
    param.src = src;
    param.secinfo = (uint64_t)&secinfo;

    /* Whether to perform EEXTEND on this page (or parts of it) */
    if (extend)
        param.mrmask = 0xffff;

    return ioctl(dev, SGX_IOC_ENCLAVE_ADD_PAGE, &param);
}

int SGX_IoctlEnclaveInit(
    int dev,
    uint64_t addr,
    uint64_t sigstruct,
    uint64_t einittoken)
{
    SGXEInitParam param;

    if (dev == -1 || !addr || !sigstruct || !einittoken)
        return -1;

    memset(&param, 0, sizeof(param));
    param.addr = addr;
    param.sigstruct = sigstruct;
    param.einittoken = einittoken;

    return ioctl(dev, SGX_IOC_ENCLAVE_INIT, &param);
}
