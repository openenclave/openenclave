// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXIOCTL_H
#define _OE_SGXIOCTL_H

#include <openenclave/bits/sgxtypes.h>

int SGX_IoctlEnclaveCreate(int dev, SGX_Secs* secs);

int SGX_IoctlEnclaveAddPage(
    int dev,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

int SGX_IoctlEnclaveInit(
    int dev,
    uint64_t addr,
    uint64_t sigstruct,
    uint64_t einittoken);

#endif /* _OE_SGXIOCTL_H */
