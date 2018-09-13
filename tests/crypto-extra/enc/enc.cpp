// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include "../common/args.h"
#include "../common/tests.cpp"

OE_ECALL void ecall_test_cert_chain_positive(void* args_)
{
    test_cert_chain_args_t* args = (test_cert_chain_args_t*)args_;
    test_cert_chain_positive(args->root, args->intermediate, args->leaf);
}

OE_ECALL void ecall_test_cert_chain_negative(void* args_)
{
    test_cert_chain_args_t* args = (test_cert_chain_args_t*)args_;
    test_cert_chain_negative(args->root, args->intermediate, args->leaf);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
