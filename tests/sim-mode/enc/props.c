// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    1234,  /* ProductID */
    5678,  /* SecurityVersion */
    false, /* Debug */
    1024,  /* NumHeapPages */
    512,   /* NumStackPages */
    4);    /* NumTCS */
