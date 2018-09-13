// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/cert.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string>
#include <vector>

oe_result_t create_and_read_chain(
    std::vector<const char*>&& certs,
    oe_cert_chain_t* chain)
{
    std::string s = "";
    for (size_t i = 0; i < certs.size(); ++i)
    {
        if (certs[i])
            s += certs[i];
    }

    oe_cert_chain_free(chain);
    // size + 1 to include null character.
    oe_result_t result = oe_cert_chain_read_pem(chain, &s[0], s.size() + 1);
    return result;
}

void test_cert_chain_positive(
    const char* root,
    const char* intermediate,
    const char* leaf,
    const char* leaf2)
{
    oe_cert_chain_t chain = {0};

    // The expected order is leaf, intermediate, root.
    // But it is inverse of open ssl order.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{leaf, intermediate, root}, &chain) ==
        OE_OK);

    // Duplicates are allowed, so long as a valid chain in correct
    // order is present. In the following, the second occurence of leaf
    // is followed by intermediate and root, allowing successful validdation.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{
                leaf, intermediate, leaf, intermediate, root},
            &chain) == OE_OK);

    // Two cert chain.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, root}, &chain) == OE_OK);

    // Two leaf certs in chain, but starts at intermediate.
    // For successful validation, for each cert in the chain, its
    // ancestor (ie it's CA certificate) must occur atleast once to
    // its right.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{
                intermediate, leaf, leaf2, intermediate, root},
            &chain) == OE_OK);

    oe_cert_chain_free(&chain);
}

void test_cert_chain_negative(
    const char* root,
    const char* intermediate,
    const char* leaf,
    const char* leaf2)
{
    oe_cert_chain_t chain = {0};

    // Incorrect order.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, leaf, root}, &chain) ==
        OE_FAILURE);

    // Reverse order.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{root, intermediate, leaf}, &chain) ==
        OE_FAILURE);

    // Order rotated 1 time.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, root, leaf}, &chain) ==
        OE_FAILURE);

    // Missing cert in chain.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{leaf, NULL, root}, &chain) == OE_FAILURE);

    // Incorrect order. Leaf2 is not followed by intermediate.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{leaf, intermediate, leaf2, root},
            &chain) == OE_FAILURE);

    oe_cert_chain_free(&chain);
}