// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include "../common/tests.cpp"
#include "crypto_crls_cert_chains_t.h"

void ecall_test_cert_chain_positive(
    const char* root,
    const char* intermediate,
    const char* leaf,
    const char* leaf2)
{
    test_cert_chain_positive(root, intermediate, leaf, leaf2);
}

void ecall_test_cert_chain_negative(
    const char* root,
    const char* intermediate,
    const char* leaf,
    const char* leaf2)
{
    test_cert_chain_negative(root, intermediate, leaf, leaf2);
}

void ecall_test_crls(
    const char* root,
    const char* intermediate,
    const char* leaf1,
    const char* leaf2,
    const char* root_crl1,
    size_t root_crl1_size,
    const char* root_crl2,
    size_t root_crl2_size,
    const char* intermediate_crl1,
    size_t intermediate_crl1_size,
    const char* intermediate_crl2,
    size_t intermediate_crl2_size)
{
    test_crls(
        root,
        intermediate,
        leaf1,
        leaf2,
        reinterpret_cast<const uint8_t*>(root_crl1),
        root_crl1_size,
        reinterpret_cast<const uint8_t*>(root_crl2),
        root_crl2_size,
        reinterpret_cast<const uint8_t*>(intermediate_crl1),
        intermediate_crl1_size,
        reinterpret_cast<const uint8_t*>(intermediate_crl2),
        intermediate_crl2_size);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
