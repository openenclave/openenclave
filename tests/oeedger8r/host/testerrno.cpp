// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <errno.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "all_u.h"

void ocall_errno()
{
    // Super unique number.
    errno = 0x12345678;
}

void ocall_set_host_errno(int e)
{
    errno = e;
}

void ocall_noop()
{
}
