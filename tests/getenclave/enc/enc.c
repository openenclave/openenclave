// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "getenclave_t.h"

oe_result_t test_get_enclave_ecall(oe_enclave_t* enclave_param)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t* enclave;

    if (!(enclave = oe_get_enclave()))
        goto done;

    if (enclave_param != enclave)
        goto done;

    if (test_get_enclave_ocall(enclave) != OE_OK)
        goto done;

    result = OE_OK;

done:
    return result;
}

#if defined(__GNUC__)
__attribute__((constructor)) void global_constructor()
{
    OE_TEST(oe_get_enclave() != NULL);
}
#endif

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    64,   /* NumStackPages */
    4);   /* NumTCS */
