// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <fstream>
#include <string>
#include <vector>
#include "../common/args.h"
#include "../common/tests.cpp"

std::vector<uint8_t> read_file(const char* path)
{
    std::ifstream f(path, std::ios::binary);
    std::vector<uint8_t> bytes = std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());

    if (bytes.empty())
    {
        printf("File %s not found\n", path);
        exit(1);
    }
    bytes.push_back('\0');
    return bytes;
}

void run_cert_chain_tests(oe_enclave_t* enclave)
{
    auto root_ca1 = read_file("./data/RootCA1.crt.pem");
    auto intermediate_ca1 = read_file("./data/IntermediateCA1.crt.pem");
    auto leaf1 = read_file("./data/Leaf1.crt.pem");
    auto leaf2 = read_file("./data/Leaf2.crt.pem");

    test_cert_chain_args_t args = {.root = (char*)&root_ca1[0],
                                   .intermediate = (char*)&intermediate_ca1[0],
                                   .leaf = (char*)&leaf1[0],
                                   .leaf2 = (char*)&leaf2[0]};
    test_cert_chain_positive(
        args.root, args.intermediate, args.leaf, args.leaf2);
    OE_TEST(
        oe_call_enclave(enclave, "ecall_test_cert_chain_positive", &args) ==
        OE_OK);

    test_cert_chain_negative(
        args.root, args.intermediate, args.leaf, args.leaf2);
    OE_TEST(
        oe_call_enclave(enclave, "ecall_test_cert_chain_negative", &args) ==
        OE_OK);
}

void run_crl_tests(oe_enclave_t* enclave)
{
    auto root_ca1 = read_file("./data/RootCA1.crt.pem");
    auto intermediate_ca1 = read_file("./data/IntermediateCA1.crt.pem");
    auto leaf1 = read_file("./data/Leaf1.crt.pem");
    auto leaf2 = read_file("./data/Leaf2.crt.pem");
    auto root_crl1 = read_file("./data/root_crl1.der");
    auto root_crl2 = read_file("./data/root_crl2.der");
    auto intermediate_crl1 = read_file("./data/intermediate_crl1.der");
    auto intermediate_crl2 = read_file("./data/intermediate_crl2.der");

    test_crl_args_t args = {
        .root = (char*)&root_ca1[0],
        .intermediate = (char*)&intermediate_ca1[0],
        .leaf1 = (char*)&leaf1[0],
        .leaf2 = (char*)&leaf2[0],
        .root_crl1 = &root_crl1[0],
        .root_crl1_size = root_crl1.size() - 1,
        .root_crl2 = &root_crl2[0],
        .root_crl2_size = root_crl2.size() - 1,
        .intermediate_crl1 = &intermediate_crl1[0],
        .intermediate_crl1_size = intermediate_crl1.size() - 1,
        .intermediate_crl2 = &intermediate_crl2[0],
        .intermediate_crl2_size = intermediate_crl2.size() - 1};
    test_crls(
        args.root,
        args.intermediate,
        args.leaf1,
        args.leaf2,
        args.root_crl1,
        args.root_crl1_size,
        args.root_crl2,
        args.root_crl2_size,
        args.intermediate_crl1,
        args.intermediate_crl1_size,
        args.intermediate_crl2,
        args.intermediate_crl2_size);

    OE_TEST(oe_call_enclave(enclave, "ecall_test_crls", &args) == OE_OK);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    /* Create the enclave */
    if ((result = oe_create_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    run_cert_chain_tests(enclave);
    run_crl_tests(enclave);

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
