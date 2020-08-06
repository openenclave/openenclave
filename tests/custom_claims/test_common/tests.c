// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "tests.h"

void _test_custom_claims_seriaize_deserialize()
{
    printf("====== begin  _test_custom_claims_seriaize_deserialize\n");
    uint8_t* claims_out = NULL;
    size_t claims_size_out = 0;
    oe_claim_t* claims1 = NULL;
    size_t claims_len = 0;

    oe_claim_t custom_claims[2] = {{.name = CLAIM1_NAME,
                                    .value = (uint8_t*)CLAIM1_VALUE,
                                    .value_size = sizeof(CLAIM1_VALUE)},
                                   {.name = CLAIM2_NAME,
                                    .value = (uint8_t*)CLAIM2_VALUE,
                                    .value_size = sizeof(CLAIM2_VALUE)}};

    printf("====== _test_custom_claims_seriaize_deserialize call "
           "oe_claims_serialize\n");
    OE_TEST(
        oe_serialize_custom_claims(
            custom_claims, 2, &claims_out, &claims_size_out) == OE_OK);

    printf("====== _test_custom_claims_serde call oe_claims_deserialize\n");
    OE_TEST(
        oe_deserialize_custom_claims(
            claims_out, claims_size_out, &claims1, &claims_len) == OE_OK);

    OE_TEST(strcmp(claims1[0].name, CLAIM1_NAME) == 0);
    OE_TEST(strcmp((char*)claims1[0].value, CLAIM1_VALUE) == 0);
    OE_TEST(strcmp(claims1[1].name, CLAIM2_NAME) == 0);
    OE_TEST(strcmp((char*)claims1[1].value, CLAIM2_VALUE) == 0);
    OE_TEST(claims_len == 2);

    for (size_t i = 0; i < claims_len; ++i)
    {
        printf(
            "====== _test_custom_claims_seriaize_deserialize claim %s %s\n",
            claims1[i].name,
            claims1[i].value);
    }

    OE_TEST(oe_free_custom_claims(claims1, claims_len) == OE_OK);
    claims_len = 0;
    claims1 = NULL;

    OE_TEST(oe_free_serialized_custom_claims(claims_out) == OE_OK);
    claims_out = NULL;
    claims_size_out = 0;

    printf("====== end _test_custom_claims_seriaize_deserialize\n");
}
