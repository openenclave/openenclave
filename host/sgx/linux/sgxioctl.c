// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgxioctl.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
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
typedef struct _sgx_ecreate_param
{
    uint64_t secs;
} SGXECreateParam;
OE_PACK_END

OE_PACK_BEGIN
typedef struct _sgx_eadd_param
{
    uint64_t addr;    /* enclaves address to copy to */
    uint64_t src;     /* user address to copy from */
    uint64_t secinfo; /* section information about this page */
    uint16_t mrmask;  /* 0xffff if extend (measurement) will be performed */
} SGXEAddParam;
OE_PACK_END

OE_PACK_BEGIN
typedef struct _sgx_einit_param
{
    uint64_t addr;
    uint64_t sigstruct;
    uint64_t einittoken;
} SGXEInitParam;
OE_PACK_END

int sgx_ioctl_enclave_create(int dev, sgx_secs_t* secs)
{
    SGXECreateParam param;
    int rc = 0;

    if (dev == -1 || !secs)
        return -1;

    memset(&param, 0, sizeof(param));
    param.secs = (uint64_t)secs;

    rc = ioctl(dev, SGX_IOC_ENCLAVE_CREATE, &param);
    if (rc)
        OE_TRACE_ERROR("rc=0x%x\n", rc);

    return rc;
}

int sgx_ioctl_enclave_add_page(
    int dev,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend)
{
    SGXEAddParam param;
    sgx_secinfo_t secinfo;
    int rc = 0;

    if (dev == -1 || !addr || !src || !flags)
        return -1;

    memset(&secinfo, 0, sizeof(sgx_secinfo_t));
    secinfo.flags = flags;

    memset(&param, 0, sizeof(param));
    param.addr = addr;
    param.src = src;
    param.secinfo = (uint64_t)&secinfo;

    /* Whether to perform EEXTEND on this page (or parts of it) */
    if (extend)
        param.mrmask = 0xffff;

    rc = ioctl(dev, SGX_IOC_ENCLAVE_ADD_PAGE, &param);
    if (rc)
        OE_TRACE_ERROR("rc=0x%x", rc);

    return rc;
}

int sgx_ioctl_enclave_init(
    int dev,
    uint64_t addr,
    uint64_t sigstruct,
    uint64_t einittoken)
{
    SGXEInitParam param;
    int rc = 0;

    if (dev == -1 || !addr || !sigstruct || !einittoken)
        return -1;

    memset(&param, 0, sizeof(param));
    param.addr = addr;
    param.sigstruct = sigstruct;
    param.einittoken = einittoken;

    rc = ioctl(dev, SGX_IOC_ENCLAVE_INIT, &param);
    if (rc)
        OE_TRACE_ERROR("rc=0x%x", rc);

    return rc;
}
