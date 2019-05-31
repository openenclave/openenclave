// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "../common/tests.cpp"
#include "crypto_crls_cert_chains_u.h"

std::string read_text_file(const char* path)
{
    std::ifstream f(path);
    if (!f.good())
    {
        printf("File %s not found\n", path);
        exit(1);
    }
    std::ostringstream buffer;
    buffer << f.rdbuf();
    return buffer.str();
}

std::vector<char> read_binary_file(const char* path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.good())
    {
        printf("File %s not found\n", path);
        exit(1);
    }
    std::ifstream::pos_type len = f.tellg();
    std::vector<char> bytes(static_cast<std::vector<char>::size_type>(len));
    f.seekg(0, std::ios::beg);
    f.read(bytes.data(), len);
    return bytes;
}

void run_cert_chain_tests(oe_enclave_t* enclave)
{
    std::string root = read_text_file("./data/root.cert.pem");
    std::string intermediate = read_text_file("./data/intermediate.cert.pem");
    std::string leaf = read_text_file("./data/leaf1.cert.pem");
    std::string leaf2 = read_text_file("./data/leaf2.cert.pem");

    test_cert_chain_positive(
        root.c_str(), intermediate.c_str(), leaf.c_str(), leaf2.c_str());
    oe_result_t result = ecall_test_cert_chain_positive(
        enclave,
        root.c_str(),
        intermediate.c_str(),
        leaf.c_str(),
        leaf2.c_str());
    OE_TEST(OE_OK == result);

    test_cert_chain_negative(
        root.c_str(), intermediate.c_str(), leaf.c_str(), leaf2.c_str());
    result = ecall_test_cert_chain_negative(
        enclave,
        root.c_str(),
        intermediate.c_str(),
        leaf.c_str(),
        leaf2.c_str());
    OE_TEST(OE_OK == result);
}

void run_crl_tests(oe_enclave_t* enclave)
{
    std::string root = read_text_file("./data/root.cert.pem");
    std::string intermediate = read_text_file("./data/intermediate.cert.pem");
    std::string leaf = read_text_file("./data/leaf1.cert.pem");
    std::string leaf2 = read_text_file("./data/leaf2.cert.pem");
    std::vector<char> root_crl1 = read_binary_file("./data/root_crl1.der");
    std::vector<char> root_crl2 = read_binary_file("./data/root_crl2.der");
    std::vector<char> intermediate_crl1 =
        read_binary_file("./data/intermediate_crl1.der");
    std::vector<char> intermediate_crl2 =
        read_binary_file("./data/intermediate_crl2.der");

    test_crls(
        root.c_str(),
        intermediate.c_str(),
        leaf.c_str(),
        leaf2.c_str(),
        reinterpret_cast<uint8_t*>(root_crl1.data()),
        root_crl1.size(),
        reinterpret_cast<uint8_t*>(root_crl2.data()),
        root_crl2.size(),
        reinterpret_cast<uint8_t*>(intermediate_crl1.data()),
        intermediate_crl1.size(),
        reinterpret_cast<uint8_t*>(intermediate_crl2.data()),
        intermediate_crl2.size());

    oe_result_t result = ecall_test_crls(
        enclave,
        root.c_str(),
        intermediate.c_str(),
        leaf.c_str(),
        leaf2.c_str(),
        root_crl1.data(),
        root_crl1.size(),
        root_crl2.data(),
        root_crl2.size(),
        intermediate_crl1.data(),
        intermediate_crl1.size(),
        intermediate_crl2.data(),
        intermediate_crl2.size());
    OE_TEST(OE_OK == result);
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
    if ((result = oe_create_crypto_crls_cert_chains_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err(
            "oe_create_crypto_crls_cert_chains_enclave(): result=%u", result);
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
