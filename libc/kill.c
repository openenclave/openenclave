// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/signal.h>

int kill(pid_t pid, int sig)
{
    return oe_kill(pid, sig);
}
