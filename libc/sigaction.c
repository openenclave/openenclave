
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/signal.h>

#define __OE_SIGACTION sigaction
#include <openenclave/corelibc/bits/sigaction.h>
#undef __OE_SIGACTION

int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
    return oe_sigaction(
        signum, (struct oe_sigaction*)act, (struct oe_sigaction*)oldact);
}
