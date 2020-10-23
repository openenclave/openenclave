// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    1234,  /* ProductID */
    5678,  /* SecurityVersion */
    {0},   /* FamilyID */
    {0},   /* ExtendedProductID */
    true,  /* Debug */
    false, /* Kss */
#ifdef NO_PAGING_SUPPORT
    /* Set smaller heap for systems without paging support. */
    2560, /* NumHeapPages */
#else
    131072, /* NumHeapPages */
#endif
    32, /* NumStackPages */
    4); /* NumTCS */
