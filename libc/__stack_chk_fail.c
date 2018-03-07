// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

void __stack_chk_fail(void);

void __stack_chk_fail(void)
{
    puts("*** Stack smashing detected!");
    abort();
}
