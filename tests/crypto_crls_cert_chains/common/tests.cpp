// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/cert.h>
#include <openenclave/internal/crypto/crl.h>
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
    // OpenSSL accepts CA (i.e. intermediate and root) in any order.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{leaf, intermediate, root}, &chain) ==
        OE_OK);

    // Duplicates are allowed, so long as a valid chain in correct
    // order is present. In the following, the second occurence of leaf
    // is followed by intermediate and root, allowing successful validation.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{
                leaf, intermediate, leaf, intermediate, root},
            &chain) == OE_OK);

    // Two cert chain.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, root}, &chain) == OE_OK);

    // Incorrect order. This is accepted and fixed internally.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, leaf, root}, &chain) ==
        OE_OK);

    // Reverse order. This is accepted and fixed internally.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{root, intermediate, leaf}, &chain) ==
        OE_OK);

    // Order rotated 1 time.
    // As a consequence, root is not last.
    // This is accepted and fixed internally.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, root, leaf}, &chain) ==
        OE_OK);

#if defined(_WIN32)
    // NOTE: Windows cert chaining implementation does not tolerate extraneous
    // certs in the cert chain which are not duplicates. Per #1593, the
    // set of idiosyncratic behaviors arising from the cert ordering code needs
    // to be simplified and tightened to strictly accept cert chains provided
    // in the expected order.
    OE_UNUSED(leaf2);
#else
    // Incorrect order. Leaf2 is not followed by intermediate.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{leaf, intermediate, leaf2, root},
            &chain) == OE_OK);

    // Two leaf certs in chain, but starts at intermediate.
    // For successful validation, each cert's issuer must also be present in the
    // chain. The order does not matter. The chain will be reordered internally
    // to leaf->intermediate->root.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{
                intermediate, leaf, leaf2, intermediate, root},
            &chain) == OE_OK);
#endif

    oe_cert_chain_free(&chain);

    printf("===test_cert_chain_positive passed\n");
}

void test_cert_chain_negative(
    const char* root,
    const char* intermediate,
    const char* leaf,
    const char* leaf2)
{
    oe_cert_chain_t chain = {0};
    OE_UNUSED(leaf2);

    // Missing cert in chain.
    OE_TEST(
        create_and_read_chain(std::vector<const char*>{leaf, root}, &chain) ==
        OE_VERIFY_FAILED);

    // Missing cert in chain.
    // Specifically root is missing.
    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{leaf, intermediate}, &chain) ==
        OE_VERIFY_FAILED);

    oe_cert_chain_free(&chain);
    printf("===test_cert_chain_negative passed\n");
}

void test_crls(
    const char* root,
    const char* intermediate,
    const char* leaf1,
    const char* leaf2,
    const uint8_t* root_crl1,
    size_t root_crl1_size,
    const uint8_t* root_crl2,
    size_t root_crl2_size,
    const uint8_t* intermediate_crl1,
    size_t intermediate_crl1_size,
    const uint8_t* intermediate_crl2,
    size_t intermediate_crl2_size)
{
    /**
     * root_crl1 and root_crl2 are issued by root.
     * root_crl1 revokes no certificates.
     * root_crl2 revokes intermediate cert.
     *
     * intermediate_crl1 and intermediate_crl2 are issued by intermediate.
     * intermediate_crl1 revokes no certificates.
     * intermediate_crl2 revokes leaf2.
     */

    /* Read and prepare data for testing */
    oe_cert_chain_t cert_chain = {0};
    oe_cert_t leaf_cert1 = {0};
    oe_cert_t leaf_cert2 = {0};
    oe_crl_t root_crl1_obj = {0};
    oe_crl_t root_crl2_obj = {0};
    oe_crl_t intermediate_crl1_obj = {0};
    oe_crl_t intermediate_crl2_obj = {0};

    OE_TEST(
        create_and_read_chain(
            std::vector<const char*>{intermediate, root}, &cert_chain) ==
        OE_OK);

    OE_TEST(oe_cert_read_pem(&leaf_cert1, leaf1, strlen(leaf1) + 1) == OE_OK);

    OE_TEST(oe_cert_read_pem(&leaf_cert2, leaf2, strlen(leaf2) + 1) == OE_OK);

    OE_TEST(
        oe_crl_read_der(&root_crl1_obj, root_crl1, root_crl1_size) == OE_OK);

    OE_TEST(
        oe_crl_read_der(&root_crl2_obj, root_crl2, root_crl2_size) == OE_OK);

    OE_TEST(
        oe_crl_read_der(
            &intermediate_crl1_obj,
            intermediate_crl1,
            intermediate_crl1_size) == OE_OK);

    OE_TEST(
        oe_crl_read_der(
            &intermediate_crl2_obj,
            intermediate_crl2,
            intermediate_crl2_size) == OE_OK);

    // The following should succeed since no crls are pased in.
    OE_TEST(oe_cert_verify(&leaf_cert1, &cert_chain, NULL, 0) == OE_OK);

    OE_TEST(oe_cert_verify(&leaf_cert2, &cert_chain, NULL, 0) == OE_OK);

    // The following should succeed since both crl1s don't revoke any
    // certificates.
    {
        oe_crl_t* crls[] = {&root_crl1_obj, &intermediate_crl1_obj};
        OE_TEST(oe_cert_verify(&leaf_cert1, &cert_chain, crls, 2) == OE_OK);

        OE_TEST(oe_cert_verify(&leaf_cert2, &cert_chain, crls, 2) == OE_OK);

        // Crls can be given in any order.
        std::swap(crls[0], crls[1]);
        OE_TEST(oe_cert_verify(&leaf_cert1, &cert_chain, crls, 2) == OE_OK);

        OE_TEST(oe_cert_verify(&leaf_cert2, &cert_chain, crls, 2) == OE_OK);
    }

    // With root_crl1 and intermediate_crl2, leaf1 should pass, but leaf2 should
    // be revoked.
    {
        oe_crl_t* crls[] = {&root_crl1_obj, &intermediate_crl2_obj};
        OE_TEST(oe_cert_verify(&leaf_cert1, &cert_chain, crls, 2) == OE_OK);

        OE_TEST(
            oe_cert_verify(&leaf_cert2, &cert_chain, crls, 2) ==
            OE_VERIFY_REVOKED);

        // Crls can be given in any order.
        std::swap(crls[0], crls[1]);
        OE_TEST(oe_cert_verify(&leaf_cert1, &cert_chain, crls, 2) == OE_OK);

        OE_TEST(
            oe_cert_verify(&leaf_cert2, &cert_chain, crls, 2) ==
            OE_VERIFY_REVOKED);
    }

    // With root_crl2 and intermediate_crl1, both leaf1 and leaf2 should fail.
    // This is because the intermediate cert has been revoked.
    {
        oe_crl_t* crls[] = {&root_crl2_obj, &intermediate_crl1_obj};
        OE_TEST(
            oe_cert_verify(&leaf_cert1, &cert_chain, crls, 2) ==
            OE_VERIFY_REVOKED);

        OE_TEST(
            oe_cert_verify(&leaf_cert2, &cert_chain, crls, 2) ==
            OE_VERIFY_REVOKED);

        // Crls can be given in any order.
        std::swap(crls[0], crls[1]);
        OE_TEST(
            oe_cert_verify(&leaf_cert1, &cert_chain, crls, 2) ==
            OE_VERIFY_REVOKED);

        OE_TEST(
            oe_cert_verify(&leaf_cert2, &cert_chain, crls, 2) ==
            OE_VERIFY_REVOKED);
    }

    // If you pass CRL for only one of the CAs (i.e. root or intermediate), then
    // verification should fail.
    {
        oe_crl_t* crls[] = {&root_crl1_obj};
        OE_TEST(
            oe_cert_verify(&leaf_cert1, &cert_chain, crls, 1) ==
            OE_VERIFY_CRL_MISSING);

        OE_TEST(
            oe_cert_verify(&leaf_cert2, &cert_chain, crls, 1) ==
            OE_VERIFY_CRL_MISSING);

        // Try out the other crl.
        crls[0] = &intermediate_crl1_obj;
        OE_TEST(
            oe_cert_verify(&leaf_cert1, &cert_chain, crls, 1) ==
            OE_VERIFY_CRL_MISSING);

        OE_TEST(
            oe_cert_verify(&leaf_cert2, &cert_chain, crls, 1) ==
            OE_VERIFY_CRL_MISSING);
    }

    /* Clean up */
    oe_crl_free(&intermediate_crl2_obj);
    oe_crl_free(&intermediate_crl1_obj);
    oe_crl_free(&root_crl2_obj);
    oe_crl_free(&root_crl1_obj);
    oe_cert_free(&leaf_cert2);
    oe_cert_free(&leaf_cert1);
    oe_cert_chain_free(&cert_chain);

    printf("===test_crls passed\n");
}
