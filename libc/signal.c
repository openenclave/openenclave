// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <signal.h>

typedef void (*sighandler_t)(int);

static void _previous_handler(int signum)
{
    (void)signum;
}

/* Silently ignore handler registrations for now. */
sighandler_t signal(int signum, sighandler_t handler)
{
    (void)signum;
    (void)handler;

    return _previous_handler;
}
