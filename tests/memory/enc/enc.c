// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    1234,                /* ProductID */
    5678,                /* SecurityVersion */
    true,                /* AllowDebug */
#ifdef NO_PAGING_SUPPORT /* Set smaller heap for systems without paging \
                            support. */
    2560,                /* HeapPageCount */
#else
    131072, /* HeapPageCount */
#endif
    32, /* StackPageCount */
    4); /* TCSCount */
