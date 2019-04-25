// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_EVENTFD_H
#define _OE_SYS_EVENTFD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

#define OE_EFD_SEMAPHORE 00000001
#define OE_EFD_CLOEXEC 02000000
#define OE_EFD_NONBLOCK 00004000

typedef uint64_t oe_eventfd_t;

int oe_eventfd(unsigned int initval, int flags);

int oe_eventfd_read(int fd, oe_eventfd_t* value);

int oe_eventfd_write(int fd, oe_eventfd_t value);

/*
**==============================================================================
**
** standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define EFD_SEMAPHORE OE_EFD_SEMAPHORE
#define EFD_CLOEXEC OE_EFD_CLOEXEC
#define EFD_NONBLOCK OE_EFD_NONBLOCK

typedef oe_eventfd_t eventfd_t;

OE_INLINE int eventfd(unsigned int initval, int flags)
{
    return oe_eventfd(initval, flags);
}

OE_INLINE int eventfd_read(int fd, eventfd_t* value)
{
    return oe_eventfd_read(fd, (oe_eventfd_t*)value);
}

OE_INLINE int eventfd_write(int fd, eventfd_t value)
{
    return oe_eventfd_write(fd, (oe_eventfd_t)value);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_EVENTFD_H */
