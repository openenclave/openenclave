// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

OE_ECALL void test_get_enclave_ecall(void* args_)
{
    oe_result_t result = OE_UNEXPECTED;
    args_t* args = (args_t*)args_;
    oe_enclave_t* enclave;

    if (!(enclave = oe_get_enclave()))
        goto done;

    if (args->enclave != enclave)
        goto done;

    if (oe_call_host("test_get_enclave_ocall", enclave) != OE_OK)
        goto done;

    args->result = OE_OK;

done:
    args->result = result;
}

#if defined(__GNUC__)
__attribute__((constructor))
void global_constructor()
{
    OE_TEST(oe_get_enclave() != NULL);
}
#endif

OE_SET_ENCLAVE_SGX(
    0, /* ProductID */
    0, /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024,  /* StackPageCount */
    4);   /* TCSCount */
