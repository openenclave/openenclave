// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVICE_H
#define _OE_BITS_DEVICE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/** Device identifiers defined by Open Enclave. */
enum
{
    /** The null device id. */
    OE_DEVID_NONE,

    /** The standard input device. */
    OE_DEVID_STDIN,

    /** The standard output device. */
    OE_DEVID_STDOUT,

    /** The standard errord evice. */
    OE_DEVID_STDERR,

    /** The non-secure host file system. */
    OE_DEVID_HOST_FILE_SYSTEM,

    /** The Intel SGX protected file system. */
    OE_DEVID_SGX_FILE_SYSTEM,

    /** The non-secure host socket device. */
    OE_DEVID_HOST_SOCKET_INTERFACE,

    /** The host epoll device. */
    OE_DEVID_HOST_EPOLL,

    /** The host eventfd device. */
    OE_DEVID_EVENTFD,
};

/** Device names defined by Open Enclave. */
#define OE_DEVICE_NAME_STDIN "oe_stdin"
#define OE_DEVICE_NAME_STDOUT "oe_stdout"
#define OE_DEVICE_NAME_STDERR "oe_stderr"
#define OE_DEVICE_NAME_HOST_FILE_SYSTEM "oe_host_file_system"
#define OE_DEVICE_NAME_SGX_FILE_SYSTEM "oe_sgx_file_system"
#define OE_DEVICE_NAME_HOST_SOCKET_INTERFACE "oe_host_socket_interface"
#define OE_DEVICE_NAME_HOST_EPOLL "oe_host_epoll"
#define OE_DEVICE_NAME_EVENTFD "oe_eventfd"

OE_EXTERNC_END

#endif // _OE_BITS_DEVICE_H
