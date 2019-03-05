/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef __OE_EVENTFD_H__
#define __OE_EVENTFD_H__
#pragma once
#include <openenclave/internal/device.h>

enum
{
    OE_EFD_SEMAPHORE = 00000001,
    OE_EFD_CLOEXEC = 02000000,
    OE_EFD_NONBLOCK = 00004000
};

typedef uint64_t oe_eventfd_t;

#ifdef cplusplus
extern "C"
{
#endif

    int oe_eventfd(unsigned int count, int flags);
    int oe_eventfd_read(int fd, oe_eventfd_t* value);
    int oe_eventfd_write(int fd, oe_eventfd_t value);

#ifdef cplusplus
}
#endif
#endif // __OE_EVENTFD_H__
