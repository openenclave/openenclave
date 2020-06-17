// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_PTHREADHOOKS_H
#define _OE_INTERNAL_PTHREADHOOKS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <pthread.h>

OE_EXTERNC_BEGIN

typedef struct _oe_pthread_hooks
{
    int (*create)(
        pthread_t* thread,
        const pthread_attr_t* attr,
        void* (*start_routine)(void*),
        void* arg);

    int (*join)(pthread_t thread, void** retval);

    int (*detach)(pthread_t thread);
} oe_pthread_hooks_t;

void oe_register_pthread_hooks(oe_pthread_hooks_t* pthread_hooks);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_PTHREADHOOKS_H */
