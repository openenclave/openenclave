// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../args.h"

OE_ECALL void Test(void* args_)
{
    Args* args = (Args*)args_;
    args->ret = 0;
}

OE_DEFINE_ENCLAVE_PROPERTIES_SGX(
    0,          /* ProductID */
    0,          /* SecurityVersion */
    true,       /* AllowDebug */
    1024,       /* HeapPageCount */
    1024,       /* StackPageCount */
    2);         /* TCSCount */

