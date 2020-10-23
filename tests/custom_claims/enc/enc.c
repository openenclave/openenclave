// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include "../test_common/tests.h"
#include "custom_claims_t.h"

int enc_custom_claims()
{
    printf("====== begin custom claim enclave tests\n");
    _test_custom_claims_seriaize_deserialize();
    printf("====== end custom claim enclave tests\n");
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,     /* ProductID */
    1,     /* SecurityVersion */
    {0},   /* FamilyID */
    {0},   /* ExtendedProductID */
    true,  /* Debug */
    false, /* Kss */
    1024,  /* NumHeapPages */
    1024,  /* NumStackPages */
    2);    /* NumTCS */
