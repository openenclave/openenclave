// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/thread.h>
#include <signal.h>

static void _handler(int signum)
{
    (void)signum;
}

static void _restorer(void)
{
}

static struct sigaction _oldact = {
    .sa_handler = _handler,
    .sa_mask = 0,
    .sa_flags = 0,
    .sa_restorer = _restorer,
};

static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

/* Silently ignore handler registrations for now. */
int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
    (void)signum;
    (void)act;

    if (oldact)
    {
        oe_spin_lock(&_lock);
        *oldact = _oldact;
        oe_spin_unlock(&_lock);
    }

    return 0;
}
