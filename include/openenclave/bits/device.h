// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVICE_H
#define _OE_BITS_DEVICE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Device identifiers known by Open Enclave.
 */
enum
{
    /** The null device id. */
    OE_DEVID_NONE,

    /** The non-secure host file system. */
    OE_DEVID_HOSTFS,

    /** The Intel SGX protected file system. */
    OE_DEVID_SGXFS,

    /** The non-secure host socket device. */
    OE_DEVID_HOSTSOCK,

    /** The host epoll device. */
    OE_DEVID_HOSTEPOLL,

    /** The host eventfd device. */
    OE_DEVID_EVENTFD,

    /** The standard input device. */
    OE_DEVID_STDIN,

    /** The standard output device. */
    OE_DEVID_STDOUT,

    /** The standard errord evice. */
    OE_DEVID_STDERR,
};

OE_EXTERNC_END

#endif // _OE_BITS_DEVICE_H
