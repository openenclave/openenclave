// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/internal/enclavelibc.h>
#include <sched.h>
#include <stdio.h>

int sched_yield(void)
{
    assert("sched_yield(): panic" == NULL);
    return -1;
}
