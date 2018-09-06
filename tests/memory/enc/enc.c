// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <stdlib.h>
#include "../args.h"

OE_SET_ENCLAVE_SGX(
    1234,   /* ProductID */
    5678,   /* SecurityVersion */
    true,   /* AllowDebug */
    131072, /* HeapPageCount */
    512,    /* StackPageCount */
    4);     /* TCSCount */
