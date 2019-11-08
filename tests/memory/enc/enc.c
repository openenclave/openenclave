// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    1234,   /* ProductID */
    5678,   /* SecurityVersion */
    true,   /* AllowDebug */
    131072, /* HeapPageCount */
    512,    /* StackPageCount */
    4);     /* TCSCount */
