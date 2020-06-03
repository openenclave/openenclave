// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    1234,   /* ProductID */
    5678,   /* SecurityVersion */
    true,   /* Debug */
    131072, /* NumHeapPages */
    32,     /* NumStackPages */
    4);     /* NumTCS */
