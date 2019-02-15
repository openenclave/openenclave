// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

void __stack_chk_fail(void)
{
    __oe_assert_fail(
        "Stack smashing detected!", __FILE__, __LINE__, __FUNCTION__);
}
