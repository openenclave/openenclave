// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/signal.h>

typedef oe_sighandler_t sighandler_t;

sighandler_t signal(int signum, sighandler_t handler)
{
    return (sighandler_t)oe_signal(signum, (oe_sighandler_t)handler);
}
