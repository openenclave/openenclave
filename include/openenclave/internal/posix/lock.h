// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_LOCK_H
#define _OE_POSIX_LOCK_H

#include <openenclave/enclave.h>

#include <openenclave/corelibc/assert.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** lock.h:
**
**     This file defines 'conditional lock' functions. These functions perform
**     their operation based on the value of the locked parameter (see function
**     descriptions below). The locked parameter must reside on the calling
**     thread's stack. Here's a typical schenario.
**
**         static oe_spinlock_t _lock;
**
**         int f(const char* name)
**         {
**             int ret = -1;
**             bool locked = false;
**
**             if (!name)
**                 goto done;
**
**             oe_conditional_lock(&_lock, locked);
**
**             // Modify the lock protected structures here!
**
**         done:
**             oe_conditional_unlock(&_lock, locked);
**             return ret;
**         }
**
**     Another scenario involves passing the locked variable onto another
**     function. For example:
**
**         static oe_spinlock_t _lock;
**
**         int f(bool* locked)
**         {
**             oe_conditional_lock(&_lock, locked);
**
**             oe_conditional_unlock(&_lock, locked);
**         }
**
**         int f(const char* name)
**         {
**             int ret = -1;
**             bool locked = false;
**
**             if (!name)
**                 goto done;
**
**             oe_conditional_lock(&_lock, locked);
**
**             // Modify the lock protected structures here!
**
**             g(locked);
**
**         done:
**             oe_conditional_unlock(&_lock, locked);
**             return ret;
**         }
**
**     If the locked parameter is null, then the associated operation is
**     performed unconditionally.
**
**==============================================================================
*/

/* Obtain the lock if *locked is false. */
oe_result_t oe_conditional_lock(oe_spinlock_t* lock, bool* locked);

/* Release the lock if *locked is true. */
oe_result_t oe_conditional_unlock(oe_spinlock_t* lock, bool* locked);

OE_EXTERNC_END

#endif // _OE_POSIX_LOCK_H
