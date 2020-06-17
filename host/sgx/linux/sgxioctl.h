// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXIOCTL_H
#define _OE_SGXIOCTL_H

#include <openenclave/bits/sgx/sgxtypes.h>

int sgx_ioctl_enclave_create(int dev, sgx_secs_t* secs);

int sgx_ioctl_enclave_add_page(
    int dev,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

int sgx_ioctl_enclave_init(
    int dev,
    uint64_t addr,
    uint64_t sigstruct,
    uint64_t einittoken);

#endif /* _OE_SGXIOCTL_H */
