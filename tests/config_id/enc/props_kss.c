// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX2(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    {0},   /* ExtendedProductID */
    {0},   /* FamilyID */
    true,  /* Debug */
    false, /* CapturePFGPExceptions */
    true,  /* RequireKSS */
    1024,  /* NumHeapPages */
    1024,  /* NumStackPages */
    1);    /* NumTCS */
