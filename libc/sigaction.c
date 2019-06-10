// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <signal.h>

static void _handler(int signum)
{
    (void)signum;
}

static void _restorer(void)
{
}

static const struct sigaction _oldact = {
    .sa_handler = _handler,
    .sa_mask = 0,
    .sa_flags = 0,
    .sa_restorer = _restorer,
};

/* Silently ignore handler registrations for now. */
int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
    (void)signum;
    (void)act;

    if (oldact)
        *oldact = _oldact;

    return 0;
}
