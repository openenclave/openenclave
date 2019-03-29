// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVID_H
#define _OE_BITS_DEVID_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_DEVID_NULL ((uint64_t)0)
#define OE_DEVID_HOSTFS ((uint64_t)1)
#define OE_DEVID_SGXFS ((uint64_t)2)
#define OE_DEVID_SHWFS ((uint64_t)3)
#define OE_DEVID_HOST_SOCKET ((uint64_t)4)
#define OE_DEVID_ENCLAVE_SOCKET ((uint64_t)5)
#define OE_DEVID_EPOLL ((uint64_t)6)
#define OE_DEVID_EVENTFD ((uint64_t)7)
#define OE_DEVID_HARDWARE_SECURE_SOCKET ((uint64_t)8)

OE_EXTERNC_END

#endif /* _OE_BITS_DEVID_H */
