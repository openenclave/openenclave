// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include "../common/args.h"
#include "../common/tests.cpp"

OE_ECALL void ecall_test_cert_chain_positive(void* args_)
{
    test_cert_chain_args_t* args = (test_cert_chain_args_t*)args_;
    test_cert_chain_positive(
        args->root, args->intermediate, args->leaf, args->leaf2);
}

OE_ECALL void ecall_test_cert_chain_negative(void* args_)
{
    test_cert_chain_args_t* args = (test_cert_chain_args_t*)args_;
    test_cert_chain_negative(
        args->root, args->intermediate, args->leaf, args->leaf2);
}

OE_ECALL void ecall_test_crls(void* args_)
{
    test_crl_args_t* args = (test_crl_args_t*)args_;
    test_crls(
        args->root,
        args->intermediate,
        args->leaf1,
        args->leaf2,
        args->root_crl1,
        args->root_crl1_size,
        args->root_crl2,
        args->root_crl2_size,
        args->intermediate_crl1,
        args->intermediate_crl1_size,
        args->intermediate_crl2,
        args->intermediate_crl2_size);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
